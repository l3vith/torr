mod parser;
use parser::Bencode;

use hex;
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use rand::thread_rng;
use rand::{Rng, distributions::Alphanumeric};
use reqwest::Client;
use sha1::{Digest, Sha1};
use std::{fs, str};
use thiserror::Error;
use tokio;
use tokio::net::UdpSocket;

#[derive(Debug, Error)]
pub enum TrackerError {
    #[error("invalid tracker URL: {0}")]
    InvalidUrl(String),

    #[error("invalid tracker action: {0}")]
    InvalidAction(u32),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("tracker request timed out")]
    Timeout,

    #[error("invalid tracker response format")]
    InvalidResponseFormat,

    #[error("invalid tracker response size")]
    InvalidResponseSize(usize),

    #[error("failed to parse bencoded data")]
    BencodeParseError,

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("tracker returned failure: {0}")]
    TrackerFailure(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

fn generate_peer_id() -> String {
    let prefix = "-RS1000-"; // RS = Rust Client, 1000 = version 1.0.0
    let random: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();

    format!("{}{}", prefix, random)
}

async fn tracker_request(
    url: &str,
    info_hash: &[u8],
    peer_id: &str,
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
) -> Result<Bencode, TrackerError> {
    let protocol = url
        .split("://")
        .next()
        .ok_or_else(|| TrackerError::InvalidUrl(url.to_string()))?;

    match protocol {
        "http" | "https" => {
            let info_hash_encoded = percent_encode(info_hash, NON_ALPHANUMERIC).to_string();
            let peer_id_encoded = percent_encode(peer_id.as_bytes(), NON_ALPHANUMERIC).to_string();
            let req = format!(
                "{}?info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact=1&event=started",
                url, info_hash_encoded, peer_id_encoded, port, uploaded, downloaded, left
            );
            let client = Client::new();
            let response = client
                .get(&req)
                .send()
                .await
                .map_err(|e| TrackerError::NetworkError(e.to_string()))?;

            let bytes = response.bytes().await.map_err(|_| TrackerError::Timeout)?;
            let (parsed_res, _) = Bencode::parse(bytes.to_vec().as_slice())
                .map_err(|_| TrackerError::BencodeParseError)?;
            Ok(parsed_res)
        }
        "udp" => {
            let socket = UdpSocket::bind("0.0.0.0:9696")
                .await
                .map_err(|e| TrackerError::Io(e))?;

            const PROTOCOL_ID: u64 = 0x41727101980;
            const ACTION_FIELD: u32 = 0;
            let transaction_id: u32 = thread_rng().r#gen();

            let mut conn_req = Vec::with_capacity(16);
            conn_req.extend_from_slice(&PROTOCOL_ID.to_be_bytes());
            conn_req.extend_from_slice(&ACTION_FIELD.to_be_bytes());
            conn_req.extend_from_slice(&transaction_id.to_be_bytes());

            let tracker_url = match url.strip_prefix("udp://") {
                Some(url) => url,
                None => return Err(TrackerError::InvalidUrl(url.to_string())),
            };

            socket
                .send_to(&conn_req, tracker_url)
                .await
                .map_err(|e| TrackerError::Io(e))?;

            let mut buffer = [0u8; 16];

            let (size, addr) = socket.recv_from(&mut buffer).await.unwrap();

            if size != 16 {
                return Err(TrackerError::InvalidResponseSize(size));
            }

            let res_action = u32::from_be_bytes(buffer[0..4].try_into().unwrap());
            let res_transaction_id = u32::from_be_bytes(buffer[4..8].try_into().unwrap());
            let res_connection_id = u64::from_be_bytes(buffer[8..16].try_into().unwrap());

            println!(
                "Received response: action={}, transaction_id={}, connection_id={}",
                res_action, res_transaction_id, res_connection_id
            );

            // Implement retrying if failure in recieving the right action id
            if res_action != 0 {
                return Err(TrackerError::InvalidAction(res_action));
            }

            // Building Anncounce Request
            const ANN_ACTION_ID: u32 = 1;
            let ann_transaction_id: u32 = thread_rng().r#gen();
            let event: u32 = 0;
            let ip_addr: u32 = 0;
            let key: u32 = thread_rng().r#gen();
            let num_want: i32 = -1;
            let port: u16 = 6881;

            let mut announce_packet: Vec<u8> = Vec::new();
            announce_packet.extend_from_slice(&res_connection_id.to_be_bytes());
            announce_packet.extend_from_slice(&ANN_ACTION_ID.to_be_bytes());
            announce_packet.extend_from_slice(&ann_transaction_id.to_be_bytes());
            announce_packet.extend_from_slice(&info_hash);
            announce_packet.extend_from_slice(&peer_id.as_bytes());
            announce_packet.extend_from_slice(&downloaded.to_be_bytes());
            announce_packet.extend_from_slice(&left.to_be_bytes());
            announce_packet.extend_from_slice(&uploaded.to_be_bytes());
            announce_packet.extend_from_slice(&event.to_be_bytes());
            announce_packet.extend_from_slice(&ip_addr.to_be_bytes());
            announce_packet.extend_from_slice(&key.to_be_bytes());
            announce_packet.extend_from_slice(&num_want.to_be_bytes());
            announce_packet.extend_from_slice(&port.to_be_bytes());

            if announce_packet.len() != 98 {
                return Err(TrackerError::InvalidResponseSize(announce_packet.len()));
            }

            println!("Sending announce request!");
            socket
                .send_to(&announce_packet, tracker_url)
                .await
                .map_err(|e| TrackerError::Io(e))?;
            println!("Recieving announce response!");

            let mut announce_buffer = vec![0u8; 4096];
            let (ann_size, ann_addr) = socket.recv_from(&mut announce_buffer).await?;

            println!("{:?}", &announce_buffer[..ann_size]);

            todo!()
        }
        _ => {
            unimplemented!()
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let bytes = fs::read("test/manjaro-gnome-25.0.10-251013-linux612.iso.torrent")?;
    let (parsed, _) = Bencode::parse(bytes.as_slice()).unwrap();

    let info = match parsed.as_dict().and_then(|d| d.get(&b"info".to_vec())) {
        Some(info) => info,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "info object not found!",
            ));
        }
    };

    // Encoding & Decoding Check
    let mut buffer = Vec::new();
    Bencode::encode(&parsed, &mut buffer)?;
    if bytes == buffer {
        println!("Encoding & Decoding Success");
    } else {
        println!("Failure in encoding/decoding!");
    }
    println!("Original: {} Encoded: {}", bytes.len(), buffer.len());

    //Info Hash (SHA1)
    let mut info_buffer = Vec::new();
    Bencode::encode(info, &mut info_buffer)?;

    let mut hasher = Sha1::new();
    hasher.update(&info_buffer);
    let info_hash_bytes = hasher.finalize();

    let info_hash: String = hex::encode(info_hash_bytes);
    println!("Info Hash: {}", info_hash);

    // Getting Announce Links
    let announce = match parsed.as_dict().and_then(|d| {
        d.get(&b"announce".to_vec())
            .or(d.get(&b"announce-list".to_vec()))
    }) {
        Some(annouce) => annouce,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "announce object not found!",
            ));
        }
    };

    println!("Announce: {}", announce.to_string());

    let announce_bytes = announce.as_string().ok_or(std::io::Error::new(
        std::io::ErrorKind::Other,
        "invalid tracker response format",
    ))?;

    let announce_string = str::from_utf8(announce_bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "bencode parse error"))?;

    let peer_id = generate_peer_id();
    let response = match tracker_request(
        announce_string,
        &info_hash_bytes,
        &peer_id,
        6881,
        0,
        0,
        1000,
    )
    .await
    {
        Ok(res) => res,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "tracker request failed",
            ));
        }
    };
    println!("Response: {}", response);

    Ok(())
}

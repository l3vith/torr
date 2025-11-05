mod parser;
mod torrent;
use parser::Bencode;

use hex;
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use rand::thread_rng;
use rand::{Rng, distributions::Alphanumeric};
use reqwest::Client;
use sha1::{Digest, Sha1};
use std::path::Path;
use std::{fs, net::Ipv4Addr, str};
use thiserror::Error;
use tokio;
use tokio::net::UdpSocket;

use crate::torrent::TorrentMetadata;

#[derive(Debug, Error)]
pub enum TrackerError {
    #[error("invalid tracker URL: {0}")]
    InvalidUrl(String),

    #[error("invalid tracker action: {0}")]
    InvalidAction(u32),

    #[error("invalid tracker protocol")]
    InvalidProtocol,

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

#[derive(Debug)]
pub struct Peer {
    ip: Ipv4Addr,
    port: u16,
}

pub struct Tracker {
    pub url: String,
    pub info_hash: [u8; 20],
    pub peer_id: String,
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
}

#[derive(Debug)]
pub struct TrackerResponse {
    pub interval: u32,
    pub leechers: u32,
    pub seeders: u32,
    pub peers: Vec<Peer>,
}

impl TrackerResponse {
    pub fn new(interval: u32, leechers: u32, seeders: u32, peers: Vec<Peer>) -> TrackerResponse {
        TrackerResponse {
            interval,
            leechers,
            seeders,
            peers,
        }
    }
}

impl Tracker {
    pub fn new(
        url: String,
        info_hash: [u8; 20],
        peer_id: String,
        port: u16,
        uploaded: u64,
        downloaded: u64,
        left: u64,
    ) -> Tracker {
        Tracker {
            url,
            info_hash,
            peer_id,
            port,
            uploaded,
            downloaded,
            left,
        }
    }

    pub fn generate_peer_id() -> String {
        let prefix = "-RS1000-"; // RS = Rust Client, 1000 = version 1.0.0
        let random: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(12)
            .map(char::from)
            .collect();

        format!("{}{}", prefix, random)
    }
}

async fn tracker_request(tracker: &Tracker) -> Result<TrackerResponse, TrackerError> {
    let protocol = tracker
        .url
        .split("://")
        .next()
        .ok_or_else(|| TrackerError::InvalidUrl(tracker.url.to_string()))?;

    match protocol {
        "http" | "https" => {
            let info_hash_encoded =
                percent_encode(&tracker.info_hash, NON_ALPHANUMERIC).to_string();
            let peer_id_encoded =
                percent_encode(tracker.peer_id.as_bytes(), NON_ALPHANUMERIC).to_string();
            let num_want = -1;
            let req = format!(
                "{}?info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact=1&event=started&numwant={}",
                tracker.url,
                info_hash_encoded,
                peer_id_encoded,
                tracker.port,
                tracker.uploaded,
                tracker.downloaded,
                tracker.left,
                num_want
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
            let res_dict = parsed_res.as_dict().ok_or(TrackerError::InvalidProtocol)?;

            let interval: u32 = res_dict
                .get(&b"interval".to_vec())
                .ok_or(TrackerError::MissingField("Interval"))?
                .as_int()
                .ok_or(TrackerError::InvalidResponseFormat)?
                .try_into()
                .map_err(|_| TrackerError::InvalidResponseFormat)?;

            let leechers: u32 = res_dict
                .get(&b"leechers".to_vec())
                .ok_or(TrackerError::MissingField("leechers"))?
                .as_int()
                .ok_or(TrackerError::InvalidResponseFormat)?
                .try_into()
                .map_err(|_| TrackerError::InvalidResponseFormat)?;

            let seeders: u32 = res_dict
                .get(&b"seeders".to_vec())
                .ok_or(TrackerError::MissingField("seeders"))?
                .as_int()
                .ok_or(TrackerError::InvalidResponseFormat)?
                .try_into()
                .map_err(|_| TrackerError::InvalidResponseFormat)?;

            let mut peers: Vec<Peer> = Vec::new();
            let peer_string = res_dict
                .get(&b"peers".to_vec())
                .ok_or(TrackerError::MissingField("seeders"))?
                .as_string()
                .ok_or(TrackerError::InvalidResponseFormat)?;

            for ip in peer_string.chunks_exact(6) {
                let ip_addr: Ipv4Addr = Ipv4Addr::from(<[u8; 4]>::try_from(&ip[0..4]).unwrap());
                let port: u16 = u16::from_be_bytes([ip[4], ip[5]]);
                peers.push(Peer { ip: ip_addr, port })
            }

            Ok(TrackerResponse::new(interval, leechers, seeders, peers))
        }
        "udp" => {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| TrackerError::Io(e))?;

            const PROTOCOL_ID: u64 = 0x41727101980;
            const ACTION_FIELD: u32 = 0;
            let transaction_id: u32 = thread_rng().r#gen();

            let mut conn_req = Vec::with_capacity(16);
            conn_req.extend_from_slice(&PROTOCOL_ID.to_be_bytes());
            conn_req.extend_from_slice(&ACTION_FIELD.to_be_bytes());
            conn_req.extend_from_slice(&transaction_id.to_be_bytes());

            let tracker_url = match tracker.url.strip_prefix("udp://") {
                Some(u) => u,
                None => return Err(TrackerError::InvalidUrl(tracker.url.to_string())),
            };

            socket
                .send_to(&conn_req, tracker_url)
                .await
                .map_err(|e| TrackerError::Io(e))?;

            let mut buffer = [0u8; 16];

            let (size, _addr) = socket.recv_from(&mut buffer).await.unwrap();

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
            announce_packet.extend_from_slice(&tracker.info_hash);
            announce_packet.extend_from_slice(&tracker.peer_id.as_bytes());
            announce_packet.extend_from_slice(&tracker.downloaded.to_be_bytes());
            announce_packet.extend_from_slice(&tracker.left.to_be_bytes());
            announce_packet.extend_from_slice(&tracker.uploaded.to_be_bytes());
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
            let (ann_size, _ann_addr) = socket.recv_from(&mut announce_buffer).await?;

            let action = u32::from_be_bytes(announce_buffer[0..4].try_into().unwrap());
            let transaction_id = u32::from_be_bytes(announce_buffer[4..8].try_into().unwrap());
            let interval = u32::from_be_bytes(announce_buffer[8..12].try_into().unwrap());
            let leechers = u32::from_be_bytes(announce_buffer[12..16].try_into().unwrap());
            let seeders = u32::from_be_bytes(announce_buffer[16..20].try_into().unwrap());

            let mut peer_list: Vec<Peer> = Vec::new();
            for chunk in announce_buffer[20..ann_size].chunks_exact(6) {
                let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&chunk[0..4]).unwrap());
                let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                peer_list.push(Peer { ip, port });
            }

            println!("Action: {}", action);
            println!("Transaction ID: {}", transaction_id);
            println!("Interval: {}", interval);
            println!("Leechers: {}", leechers);
            println!("Seeders: {}", seeders);
            println!("Peer List: {}", peer_list.len());

            Ok(TrackerResponse::new(interval, leechers, seeders, peer_list))
        }
        _ => Err(TrackerError::InvalidProtocol),
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

    let peer_id = Tracker::generate_peer_id();
    let tracker = Tracker::new(
        announce_string.to_string(),
        info_hash_bytes.into(),
        peer_id,
        6881,
        0,
        0,
        1000,
    );
    let response = match tracker_request(&tracker).await {
        Ok(res) => res,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "tracker request failed",
            ));
        }
    };
    println!("Response: {:?}", response);

    println!("------------------------------------");
    let metadata = TorrentMetadata::from_file(Path::new(
        "test/test_folder-d984f67af9917b214cd8b6048ab5624c7df6a07a.torrent",
    ));
    println!("{}", metadata.unwrap());

    Ok(())
}

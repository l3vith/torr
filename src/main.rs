mod parser;
use parser::Bencode;

use hex;
use percent_encoding::percent_encode;
use percent_encoding::{NON_ALPHANUMERIC, PercentEncode};
use rand::{Rng, distributions::Alphanumeric};
use reqwest::Client;
use sha1::{Digest, Sha1};
use std::{fs, str};
use thiserror::Error;
use tokio;

#[derive(Debug, Error)]
pub enum TrackerError {
    #[error("invalid tracker URL: {0}")]
    InvalidUrl(String),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("tracker request timed out")]
    Timeout,

    #[error("invalid tracker response format")]
    InvalidResponseFormat,

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
            unimplemented!()
        }
        _ => {
            unimplemented!()
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let bytes = fs::read("test/ubuntu-25.10-desktop-amd64.iso.torrent")?;
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

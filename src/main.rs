mod parser;
mod torrent;
mod tracker;
use parser::Bencode;

use hex;
use rand::thread_rng;
use rand::{Rng, distributions::Alphanumeric};
use reqwest::Client;
use sha1::{Digest, Sha1};
use std::path::Path;
use std::{fs, net::Ipv4Addr, str};
use thiserror::Error;
use tokio;
use tokio::net::UdpSocket;

use crate::torrent::{Torrent, TorrentMetadata};
use crate::tracker::Tracker;

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

    let mut tracker = Tracker::new(announce_string.to_string(), 6881, 0, 0, 1000);

    let metadata = TorrentMetadata::from_file(Path::new(
        "test/test_folder-d984f67af9917b214cd8b6048ab5624c7df6a07a.torrent",
    ))
    .unwrap();
    let mut torr = Torrent::new(metadata.clone());
    let response = match tracker
        .tracker_request(
            &TorrentMetadata::get_info_hash(&parsed).unwrap(),
            torr.peer_id.clone(),
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
    println!("Response: {:?}", response);

    println!("------------------------------------");

    println!("{}", metadata);
    torr.initialize_trackers();
    println!("{:#?}", torr);

    Ok(())
}

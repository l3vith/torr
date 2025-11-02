mod parser;
use parser::Bencode;

use sha1::{Digest, Sha1};
use std::fs;

fn main() -> std::io::Result<()> {
    let bytes = fs::read("test/test_folder-d984f67af9917b214cd8b6048ab5624c7df6a07a.torrent")?;
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

    let mut info_buffer = Vec::new();
    Bencode::encode(info, &mut info_buffer)?;

    //Info Hash (SHA1)
    let info_hash = Sha1::digest(&info_buffer);
    println!("Info Hash: {:x}", info_hash);

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

    println!("Announce: {:?}", announce);

    Ok(())
}

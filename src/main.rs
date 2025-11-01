mod parser;
use parser::Bencode;

use std::fs;

fn main() -> std::io::Result<()> {
    let bytes = fs::read("test/manjaro-gnome-25.0.10-251013-linux612.iso.torrent")?;
    let (parsed, _) = Bencode::parse(bytes.as_slice()).unwrap();

    if let Some(info) = parsed
        .as_dict()
        .and_then(|d| d.get(&b"info".to_vec()))
        .and_then(|v| v.as_dict())
    {
        println!("{:?}", info);
    }

    let mut buffer = Vec::new();
    Bencode::encode(&parsed, &mut buffer)?;
    if bytes == buffer {
        println!("Encoding & Decoding Success");
    } else {
        println!("Failure in encoding/decoding!");
        println!("Original: {} Encoded: {}", bytes.len(), buffer.len())
    }

    Ok(())
}

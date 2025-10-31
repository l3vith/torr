mod parser;
use parser::Bencode;

use std::fs;

fn main() -> std::io::Result<()> {
    let bytes = fs::read("test/test_folder-d984f67af9917b214cd8b6048ab5624c7df6a07a.torrent")?;
    let (parsed, _) = Bencode::parse(bytes.as_slice()).unwrap();
    println!("{}", parsed);

    Ok(())
}

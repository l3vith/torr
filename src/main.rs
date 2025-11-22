mod parser;
mod peer;
mod torrent;
mod tracker;
use parser::Bencode;

use hex;
use rand::Rng;
use sha1::{Digest, Sha1};
use std::path::Path;
use tokio;

use crate::peer::handshake;
use crate::torrent::{Torrent, TorrentMetadata};
use crate::tracker::Tracker;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let metadata = TorrentMetadata::from_file(Path::new(
        "test/manjaro-gnome-25.0.10-251013-linux612.iso.torrent",
    ))
    .unwrap();
    let mut torr = Torrent::new(metadata.clone());
    torr.initialize_trackers();
    let mut trackers: Vec<Tracker> = torr
        .trackers
        .iter()
        .flat_map(|tier| tier.iter())
        .map(|t| t.clone())
        .collect();

    for tracker in trackers.iter_mut() {
        torr.populate_peers(&tracker).await;
    }

    for peer in torr.peers.iter() {
        println!("Trying: {}", peer.ip);
        let stream = match handshake(
            peer,
            &torr.metadata.info_hash,
            torr.peer_id.as_bytes().try_into().unwrap(),
        )
        .await
        {
            Ok(a) => a,
            Err(_) => {
                eprintln!("Handshake failed");
                continue;
            }
        };
    }

    Ok(())
}

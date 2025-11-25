mod parser;
mod peer;
mod torrent;
mod tracker;
use parser::Bencode;
use rand::Rng;
use std::path::Path;
use tokio;
use tokio::sync::mpsc::channel;
use tokio::task::JoinHandle;

use crate::peer::{PeerSession, handshake};
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

    let torr_tx = torr.send_channel.clone();

    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    for peer in torr.peers.clone() {
        println!("Trying: {}", peer.ip);

        let info_hash = torr.metadata.info_hash.clone();
        let peer_id: [u8; 20] = torr.peer_id.as_bytes().try_into().unwrap();
        let pieces_count = torr.metadata.pieces.len() as usize;

        let torr_tx = torr_tx.clone();

        let handle = tokio::spawn(async move {
            match handshake(&peer, &info_hash, &peer_id).await {
                Ok((read_half, write_half)) => {
                    let (peer_tx, peer_rx) = channel(32);

                    let mut session =
                        PeerSession::new(write_half, peer.clone(), peer_id, pieces_count, torr_tx, peer_rx);
                    
                    // Complete comms for peer 
                    // add mpsc to actually send a message 
                    // on session the peer sends its tx to the torrent struct
                    session.start_loop(read_half).await.ok();
                }
                Err(err) => {
                    eprintln!("Handshake failed: {}", err);
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }

    Ok(())
}

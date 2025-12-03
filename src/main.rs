mod parser;
mod peer;
mod piece;
mod torrent;
mod tracker;

use parser::Bencode;
use rand::Rng;
use std::path::Path;
use tokio;
use tokio::sync::mpsc::channel;
use tokio::task::JoinHandle;

use crate::peer::{MainMessage, PeerSession, handshake};
use crate::torrent::{Command, Torrent, TorrentMetadata};
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
        // Create Peer Communication Channels (Peer - to - Main)
        // & push to the Torrent hashmap
        let (peer_tx, peer_rx) = channel::<Command>(32);
        torr.peer_comms.insert(peer.clone(), peer_tx);

        let info_hash = torr.metadata.info_hash.clone();
        let peer_id: [u8; 20] = torr.peer_id.as_bytes().try_into().unwrap();
        let pieces_count = torr.metadata.pieces.len() as usize;

        let torr_tx = torr_tx.clone();
        let torrent_bitfield = torr.bitfield.clone();

        let handle = tokio::spawn(async move {
            match handshake(&peer, &info_hash, &peer_id).await {
                Ok((read_half, write_half)) => {
                    let mut session = PeerSession::new(
                        write_half,
                        peer.clone(),
                        peer_id,
                        pieces_count,
                        torr_tx,
                        peer_rx,
                        torrent_bitfield,
                    );

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

    let mut recv = torr.recv_channel;

    torr.queue
        .extend((0..torr.metadata.pieces.len() - 1).map(|x| x as u32));

    let recv_loop = tokio::spawn(async move {
        loop {
            while let Some(msg) = recv.recv().await {
                match msg {
                    MainMessage::Bitfield { peer, bitfield } => {
                        println!("Bitfield Recieved From: {:#?}", peer);
                        torr.peer_bitfields.insert(peer, bitfield);
                    }
                    MainMessage::BlockRecieved {
                        piece_index,
                        begin_offset,
                        block_data,
                    } => {
                        torr.manager
                            .add_piece(piece_index, begin_offset, block_data);
                    }
                    MainMessage::UpdateBitfield {
                        peer,
                        byte_idx,
                        byte_offset,
                    } => {
                        torr.peer_bitfields.get_mut(&peer).unwrap()[byte_idx as usize] |=
                            1 << (7 - byte_offset);
                    }
                    _ => println!("Recieved: {:#?}", msg),
                }
            }
        }
    });

    handles.push(recv_loop);

    for h in handles {
        let _ = h.await;
    }

    Ok(())
}

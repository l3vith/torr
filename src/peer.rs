use std::mem::needs_drop;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::RwLock;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::timeout;

use crate::torrent::Command;

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Handshake Failed: {0}")]
    HandshakeFailure(String),

    #[error("Peer Error: {0}")]
    PeerWireError(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Peer {
    pub ip: Ipv4Addr,
    pub port: u16,
}

pub struct PeerState {
    pub am_choking: bool,
    pub am_interested: bool,
    pub peer_choking: bool,
    pub peer_interested: bool,

    pub bitfield: Vec<u8>,
    pub pieces_count: usize,

    pub supports_extensions: bool,
}

pub struct PeerSession {
    pub writer: OwnedWriteHalf,
    pub state: PeerState,

    pub peer_addr: Peer,
    pub peer_id: [u8; 20],
    // Initialize a channel for communication with main thread
    // mpsc channel
    pub send_channel: Sender<MainMessage>,
    pub recv_channel: Receiver<Command>,

    pub torrent_bitfield: Arc<RwLock<Vec<u8>>>,
}

enum InternalMessage {
    Message { id: u8, payload: Vec<u8> },
    NetworkError(PeerError),
}

#[derive(Debug)]
pub enum MainMessage {
    BlockRecieved {
        piece_index: u32,
        begin_offset: u32,
        block_data: Vec<u8>,
    },
    Bitfield {
        peer: Peer,
        bitfield: Vec<u8>,
    },
    UpdateBitfield {
        peer: Peer,
        byte_idx: u32,
        byte_offset: u32,
    }
}

// Handshake Function
pub async fn handshake(
    peer: &Peer,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
) -> Result<(OwnedReadHalf, OwnedWriteHalf), PeerError> {
    let connect_future = TcpStream::connect((peer.ip, peer.port));
    let mut stream = match timeout(Duration::from_secs(5), connect_future).await {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => return Err(PeerError::HandshakeFailure(e.to_string())),
        Err(_) => return Err(PeerError::HandshakeFailure("Timeout Exceeded".to_string())),
    };

    let pstrlen: u8 = 19;
    let pstr: &[u8; 19] = b"BitTorrent protocol";
    let reserved: [u8; 8] = [0; 8];

    let mut buff = [0u8; 68];
    buff[0] = pstrlen;
    buff[1..20].copy_from_slice(pstr);
    buff[20..28].copy_from_slice(&reserved);
    buff[28..48].copy_from_slice(info_hash);
    buff[48..68].copy_from_slice(peer_id);

    stream
        .write_all(&buff)
        .await
        .map_err(|e| PeerError::HandshakeFailure(e.to_string()))?;

    let mut res_buff = [0u8; 68];
    stream
        .read_exact(&mut res_buff)
        .await
        .map_err(|e| PeerError::HandshakeFailure(e.to_string()))?;

    // Verify Handshake Response
    let res_pstrlen = res_buff[0];
    let res_pstr = &res_buff[1..20];
    let res_info_hash = &res_buff[28..48];
    if res_pstrlen != pstrlen || res_pstr != pstr || res_info_hash != info_hash.as_slice() {
        println!("Handshake Response Mismatch");
        return Err(PeerError::HandshakeFailure(
            "Invalid handshake response".to_string(),
        ));
    }

    println!("Handshake Successful: {}", peer.ip);

    Ok(stream.into_split())
}

impl PeerSession {
    pub fn new(
        writer: OwnedWriteHalf,
        peer_addr: Peer,
        peer_id: [u8; 20],
        pieces_count: usize,
        send_channel: Sender<MainMessage>,
        recv_channel: Receiver<Command>,
        torrent_bitfield: Arc<RwLock<Vec<u8>>>,
    ) -> Self {
        let bitfield_len = pieces_count.div_ceil(8);
        PeerSession {
            writer: writer,
            state: PeerState {
                am_choking: true,
                am_interested: false,
                peer_choking: true,
                peer_interested: false,
                bitfield: vec![0; bitfield_len],
                pieces_count: pieces_count,
                supports_extensions: false,
            },
            peer_addr: peer_addr,
            peer_id: peer_id,

            send_channel: send_channel,
            recv_channel: recv_channel,

            torrent_bitfield: torrent_bitfield,
        }
    }

    pub async fn send_message(&mut self, id: u8, payload: Vec<u8>) -> Result<(), PeerError> {
        let len = (1 + payload.len()) as u32;
        self.writer.write_u32(len).await.map_err(|e| {
            PeerError::PeerWireError(format!("Failed to write length prefix: {e}").to_string())
        })?;
        self.writer.write_u8(id).await.map_err(|e| {
            PeerError::PeerWireError(format!("Failed to write message ID: {e}").to_string())
        })?;
        self.writer.write_all(&payload).await.map_err(|e| {
            PeerError::PeerWireError(format!("Failed to write message payload: {e}").to_string())
        })?;
        Ok(())
    }

    pub async fn send_interested(&mut self) -> Result<(), PeerError> {
        if self.state.am_interested {
            // Don't spam
            return Ok(());
        }

        self.state.am_interested = true;
        self.send_message(2, vec![]).await
    }

    pub async fn start_loop(&mut self, mut reader: OwnedReadHalf) -> Result<(), PeerError> {
        let (tx, mut rx) = mpsc::channel::<InternalMessage>(128);

        let stream_read = tokio::spawn(async move {
            loop {
                let mut length_buf = [0u8; 4];
                let read_len = reader.read_exact(&mut length_buf).await;
                if let Err(e) = read_len {
                    let e = PeerError::PeerWireError(format!("Failed to read length prefix: {e}"));
                    let _ = tx.send(InternalMessage::NetworkError(e)).await;
                    return;
                }

                let length_prefix = match length_buf.try_into() {
                    Ok(bytes) => u32::from_be_bytes(bytes),
                    Err(_) => {
                        let err = PeerError::PeerWireError("Invalid Length Prefix".into());
                        let _ = tx.send(InternalMessage::NetworkError(err)).await;
                        return;
                    }
                };

                if length_prefix == 0 {
                    continue;
                }

                let mut id_buf = [0u8; 1];
                let read_id = reader.read_exact(&mut id_buf).await;
                if let Err(e) = read_id {
                    let e = PeerError::PeerWireError(format!("Failed to read ID: {e}"));
                    let _ = tx.send(InternalMessage::NetworkError(e)).await;
                    return;
                }

                let id = match id_buf.try_into() {
                    Ok(bytes) => u8::from_be_bytes(bytes),
                    Err(_) => {
                        let err = PeerError::PeerWireError("Invalid Id".into());
                        let _ = tx.send(InternalMessage::NetworkError(err)).await;
                        return;
                    }
                };

                let mut payload: Vec<u8> = vec![0u8; length_prefix as usize - 1];
                if length_prefix as usize - 1 > 0 {
                    let read_payload = reader.read_exact(&mut payload).await;
                    if let Err(e) = read_payload {
                        let err = PeerError::PeerWireError(format!("Failed to read payload: {e}"));
                        let _ = tx.send(InternalMessage::NetworkError(err)).await;
                        return;
                    }
                }

                if tx
                    .send(InternalMessage::Message { id, payload })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // Main Loop (Command & Processing)
        loop {
            tokio::select! {
                Some(msg_internal) = rx.recv() => {
                    match msg_internal {
                        InternalMessage::NetworkError(e) => {
                            return Err(e)
                        },
                        InternalMessage::Message {id, payload} => {
                            match id {
                                0 => self.handle_choke().await?,
                                1 => self.handle_unchoke().await?,
                                2 => self.handle_interested().await?,
                                3 => self.handle_not_interested().await?,
                                4 => self.handle_have(payload).await?,
                                5 => self.handle_bitfield(payload).await?,
                                6 => self.handle_request(payload).await?,
                                7 => self.handle_piece(payload).await?,
                                8 => self.handle_cancel().await?,
                                9 => self.handle_port().await?,
                                20 => self.handle_extended().await?,
                                _ => println!("Unknown Message ID: {}", id),
                            }
                        },
                    }
                },

                Some(msg_main) = self.recv_channel.recv() => {
                    match msg_main {
                        Command::RequestPiece { piece_index, begin_offset, block_length } => {
                            println!("Received request for piece {}, offset {}, length {}", piece_index, begin_offset, block_length);
                            self.request_piece(piece_index, begin_offset, block_length).await?;
                        }
                    }
                }
            }
        }
    }

    async fn request_piece(
        &mut self,
        piece_index: u32,
        begin_offset: u32,
        block_length: u32,
    ) -> Result<(), PeerError> {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&piece_index.to_be_bytes());
        payload.extend_from_slice(&begin_offset.to_be_bytes());
        payload.extend_from_slice(&block_length.to_be_bytes());
        self.send_message(6, payload).await?;
        Ok(())
    }

    async fn handle_choke(&mut self) -> Result<(), PeerError> {
        self.state.peer_choking = true;
        Ok(())
    }

    async fn handle_unchoke(&mut self) -> Result<(), PeerError> {
        self.state.peer_choking = false;
        println!("Peer {} has UNCHOKED us", self.peer_addr.ip);
        Ok(())
    }

    async fn handle_interested(&mut self) -> Result<(), PeerError> {
        self.state.peer_interested = true;
        Ok(())
    }

    async fn handle_not_interested(&mut self) -> Result<(), PeerError> {
        self.state.peer_interested = false;
        Ok(())
    }

    async fn handle_have(&mut self, payload: Vec<u8>) -> Result<(), PeerError> {
        let piece_idx_arr: [u8; 4] = payload
            .as_slice()
            .try_into()
            .map_err(|e| PeerError::PeerWireError("Wrong payload: Have".to_string()))?;

        let piece_idx = u32::from_be_bytes(piece_idx_arr);

        let byte_index = piece_idx / 8;
        let byte_offset = piece_idx % 8;

        self.state.bitfield[byte_index as usize] |= 1 << (7 - byte_offset);

        if self.check_if_needed().await {
            println!(
                "Reacting to HAVE: Sending interested to peer: {} : {}",
                self.peer_addr.ip, self.peer_addr.port
            );
            self.send_interested().await?;
        }

        Ok(())
    }

    async fn check_if_needed(&mut self) -> bool {
        let bf_self = &self.state.bitfield;
        let bf_torrent = self.torrent_bitfield.read().await;

        if bf_torrent.len() != bf_self.len() {
            panic!("Bitfield length mismatch!");
        } else {
            for (a, b) in bf_self.iter().zip(bf_torrent.iter()) {
                let inverted = !b;
                let needed = a & inverted;

                if needed != 0 {
                    return true;
                }
            }
        }

        return false;
    }

    async fn handle_bitfield(&mut self, payload: Vec<u8>) -> Result<(), PeerError> {
        // Validate payload length with pieces / 8

        if payload.len() != self.state.bitfield.len() {
            Err(PeerError::PeerWireError("Bitfield Mismatch!".to_string()))?;
        }

        self.state.bitfield = payload;

        self.send_channel
            .send(MainMessage::Bitfield {
                peer: self.peer_addr.clone(),
                bitfield: self.state.bitfield.clone(),
            })
            .await
            .map_err(|e| PeerError::PeerWireError("Failed to send bitfield to main".to_string()))?;

        // Check if peer has pieces that are needed

        if self.check_if_needed().await {
            println!(
                "Sending interested to peer: {} : {}",
                self.peer_addr.ip, self.peer_addr.port
            );
            self.send_interested().await?;
        }

        Ok(())
    }

    fn _print_bitfield(&mut self) {
        for bytes in self.state.bitfield.clone() {
            for idx in 0..8 {
                let bit = (bytes >> (7 - idx)) & 1;
                if bit == 1 {
                    print!("█");
                } else {
                    print!("░");
                }
            }
        }
    }

    async fn handle_request(&mut self, payload: Vec<u8>) -> Result<(), PeerError> {
        todo!()
    }

    async fn handle_piece(&mut self, payload: Vec<u8>) -> Result<(), PeerError> {
        let piece_index: u32 = u32::from_be_bytes(
            payload[..4]
                .try_into()
                .map_err(|e| PeerError::PeerWireError("Invalid payload".to_string()))?,
        );

        let begin_offset: u32 = u32::from_be_bytes(
            payload[4..8]
                .try_into()
                .map_err(|e| PeerError::PeerWireError("Invalid payload".to_string()))?,
        );

        let block_data: Vec<u8> = payload[8..].to_vec();
        println!("Received piece {}", piece_index);
        self.send_channel
            .send(MainMessage::BlockRecieved {
                piece_index,
                begin_offset,
                block_data,
            })
            .await
            .map_err(|e| PeerError::PeerWireError("Failed to send message".to_string()))?;

        Ok(())
    }

    async fn handle_cancel(&mut self) -> Result<(), PeerError> {
        todo!()
    }

    async fn handle_port(&mut self) -> Result<(), PeerError> {
        todo!()
    }

    async fn handle_extended(&mut self) -> Result<(), PeerError> {
        todo!()
    }
}

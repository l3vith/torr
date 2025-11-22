use std::net::Ipv4Addr;
use std::time::Duration;
use thiserror::Error;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::timeout;

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
    pub stream: TcpStream,
    pub state: PeerState,

    pub peer_addr: Peer,
    pub peer_id: [u8; 20],
    // Initialize a channel for communication with main thread
    // mpsc channel
    pub send_channel: Sender<u32>,
    pub recv_channel: Receiver<u32>
}

// Handshake Function
pub async fn handshake(
    peer: &Peer,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
) -> Result<TcpStream, PeerError> {
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

    Ok(stream)
}

impl PeerSession {
    pub fn new(stream: TcpStream, peer_addr: Peer, peer_id: [u8; 20], pieces_count: usize, send_channel: Sender<u32>, recv_channel: Receiver<u32>) -> Self {
        let bitfield_len = pieces_count.div_ceil(8);
        PeerSession {
            stream: stream,
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
            recv_channel: recv_channel
        }
    }

    pub async fn send_message(&mut self, id: u8, payload: Vec<u8>) -> Result<(), PeerError> {
        let len = (1 + payload.len()) as u32;
        self.stream.write_u32(len).await.map_err(|e| {
            PeerError::PeerWireError(format!("Failed to write length prefix: {e}").to_string())
        })?;
        self.stream.write_u8(id).await.map_err(|e| {
            PeerError::PeerWireError(format!("Failed to write message ID: {e}").to_string())
        })?;
        self.stream.write_all(&payload).await.map_err(|e| {
            PeerError::PeerWireError(format!("Failed to write message payload: {e}").to_string())
        })?;
        Ok(())
    }

    pub async fn send_interested(&mut self) -> Result<(), PeerError> {
        self.send_message(2, vec![]).await
    }

    pub async fn start_loop(&mut self) -> Result<(), PeerError> {
        loop {
            let mut length_buf = [0u8; 4];
            self.stream.read_exact(&mut length_buf).await.map_err(|e| {
                PeerError::PeerWireError(format!("Unexpected EOF!: {e}").to_string())
            })?;

            let length_prefix = u32::from_be_bytes(
                length_buf
                    .try_into()
                    .map_err(|e| PeerError::PeerWireError("Invalid Length Prefix".to_string()))?,
            );

            if length_prefix == 0 {
                continue;
            }

            let mut id_buf = [0u8; 1];
            self.stream.read_exact(&mut id_buf).await.map_err(|e| {
                PeerError::PeerWireError(format!("Unexpected EOF!: {e}").to_string())
            })?;

            let id = u8::from_be_bytes(
                id_buf
                    .try_into()
                    .map_err(|e| PeerError::PeerWireError("Invalid Id".to_string()))?,
            );

            let mut payload: Vec<u8> = vec![0u8; length_prefix as usize - 1];
            if length_prefix as usize - 1 > 0 {
                self.stream.read_exact(&mut payload).await.map_err(|e| {
                    PeerError::PeerWireError(format!("Unexpected EOF!: {e}").to_string())
                })?;
            }

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
                _ => todo!(),
            }
        }
    }

    async fn handle_choke(&mut self) -> Result<(), PeerError> {
        self.state.peer_choking = true;
        Ok(())
    }

    async fn handle_unchoke(&mut self) -> Result<(), PeerError> {
        self.state.peer_choking = false;
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

        Ok(())
    }
    
    fn check_if_needed(&mut self) {
        todo!();
    }

    async fn handle_bitfield(&mut self, payload: Vec<u8>) -> Result<(), PeerError> {
        // Validate payload length with pieces / 8

        if payload.len() != self.state.bitfield.len() {
            Err(PeerError::PeerWireError("Bitfield Mismatch!".to_string()))?;
        }

        self.state.bitfield = payload;
        
        // Check if peer has pieces that are needed
        
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
        todo!()
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

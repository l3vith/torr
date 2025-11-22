use std::net::Ipv4Addr;
use std::time::Duration;
use thiserror::Error;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Handshake Failed: {0}")]
    HandshakeFailure(String),
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

    pub read_buffer: Vec<u8>,
    // Initialize a channel for communication with main thread
    // mpsc channel
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
    pub fn new(stream: TcpStream, state: PeerState, peer_addr: Peer, peer_id: [u8; 20]) -> Self {
        PeerSession {
            stream: stream,
            state: state,
            peer_addr: peer_addr,
            peer_id: peer_id,
            read_buffer: Vec::with_capacity(4096),
        }
    }
}

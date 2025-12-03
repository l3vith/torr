use sha1::{Digest, Sha1};
use std::collections::HashMap;

#[derive(Debug)]
pub struct Piece {
    index: u32,
    data: Vec<u8>,
    recieved: Vec<bool>,
    piece_size: u64,
}

#[derive(Debug)]
pub struct PieceManager {
    pieces: HashMap<u32, Piece>,
    complete_pieces: Vec<u8>,
    hashes: Vec<[u8; 20]>,
    total_pieces: u32,
    piece_length: u32,
    total_length: u64,
}

impl PieceManager {
    pub fn new(
        total_pieces: u32,
        piece_length: u32,
        total_length: u64,
        hashes: Vec<[u8; 20]>,
    ) -> Self {
        PieceManager {
            pieces: HashMap::new(),
            complete_pieces: vec![0u8; total_pieces as usize],
            hashes,
            total_pieces,
            piece_length,
            total_length,
        }
    }

    pub fn add_piece(&mut self, index: u32, offset: u32, data: Vec<u8>) -> Option<Piece> {
        // Calculate Index to check if its the last piece (can be <= piece length)
        let piece_length;
        if index as usize == self.total_pieces as usize - 1 {
            piece_length = {
                if self.total_length % self.piece_length as u64 == 0 {
                    self.piece_length as u64
                } else {
                    self.total_length % self.piece_length as u64
                }
            }
        } else {
            piece_length = self.piece_length as u64;
        }

        if let Some(piece) = self.pieces.get_mut(&index) {
            piece.add_block(offset, data).ok();
        } else {
            self.pieces
                .insert(index, Piece::new(index, piece_length as u64));
            self.pieces
                .get_mut(&index)
                .unwrap()
                .add_block(offset, data)
                .ok();
        }

        println!("Added Piece: {}", index);

        let is_complete;
        if let Some(piece) = self.pieces.get(&index) {
            is_complete = piece.is_complete();
        } else {
            is_complete = false;
        }

        if is_complete {
            let piece = self.pieces.remove(&index).unwrap();

            if piece.verify(&self.hashes[index as usize]) {
                self.complete_pieces[index as usize] = 1;
                return Some(piece);
            }
        } else {
            return None;
        }

        None
    }
}

const BLOCK_SIZE: u32 = 16 * 1024;

impl Piece {
    pub fn new(index: u32, piece_size: u64) -> Self {
        let num_blocks = piece_size.div_ceil(BLOCK_SIZE as u64);
        Piece {
            index,
            data: vec![0; piece_size as usize],
            recieved: vec![false; num_blocks as usize],
            piece_size,
        }
    }

    pub fn add_block(&mut self, offset: u32, data: Vec<u8>) -> Result<(), String> {
        let block_index = offset / BLOCK_SIZE;
        let block_length = data.len() as u32;

        if block_index >= self.recieved.len() as u32 {
            return Err("Block Index Invalid".to_string());
        }

        if (offset + block_length) as usize > self.data.len() {
            println!("Block out of bounds");
            return Err("Block out of bounds".to_string());
        }

        self.data[offset as usize..offset as usize + block_length as usize]
            .copy_from_slice(data.as_slice());
        self.recieved[block_index as usize] = true;

        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        for block in &self.recieved {
            if *block == false {
                return false;
            }
        }
        return true;
    }

    pub fn verify(&self, hash: &[u8; 20]) -> bool {
        let mut hasher = Sha1::new();
        hasher.update(&self.data);
        let result: [u8; 20] = hasher.finalize().into();

        if *hash == result {
            println!("Piece {} verified", self.index);
            return true;
        } else {
            println!("Piece {} verification failed", self.index);
            return false;
        }
    }
}

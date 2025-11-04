use std::convert::Infallible;
use std::fs::read;

use crate::Bencode;
use crate::Tracker;
use crate::{Peer, TrackerError};

use sha1::Digest;
use sha1::Sha1;
use std::io;
use std::path::Path;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TorrentError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Bencode parse error: {0}")]
    Bencode(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid torrent metadata: {0}")]
    InvalidMetadata(String),

    #[error("UTF-8 decoding error: {0}")]
    Utf8(#[from] FromUtf8Error),

    #[error("Hash computation error: {0}")]
    HashError(String),

    #[error("Tracker error: {0}")]
    TrackerError(String),

    #[error("Unknown or unexpected error: {0}")]
    Other(String),
}

#[derive(Debug)]
pub struct TorrentMetadata {
    // from info dictionary
    pub info_hash: [u8; 20],
    pub name: String,
    pub piece_length: u64,
    pub pieces: Vec<[u8; 20]>,
    pub files: Vec<TorrentFile>,

    // top-level fields
    pub announce: Option<String>,
    pub announce_list: Option<Vec<String>>,
    pub creation_date: Option<u64>,
    pub comment: Option<String>,
    pub created_by: Option<String>,
    pub encoding: Option<String>,
    pub is_private: bool,

    // web seed support (BEP-17 / BEP-19)
    pub web_seeds: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct TorrentFile {
    pub length: u64,
    pub path: String,
    pub md5sum: Option<String>,
}

pub struct Torrent {
    pub metadata: TorrentMetadata,
    pub trackers: Vec<Tracker>,
    pub peers: Vec<Peer>,
    // Implement another struct for handling state of torrent downloads
}

impl TorrentFile {
    pub fn new(length: u64, path: String, md5sum: Option<String>) -> Self {
        TorrentFile {
            length,
            path,
            md5sum,
        }
    }
}

impl TorrentMetadata {
    pub fn new(
        info_hash: [u8; 20],
        name: String,
        piece_length: u64,
        pieces: Vec<[u8; 20]>,
        files: Vec<TorrentFile>,
        announce: Option<String>,
        announce_list: Option<Vec<String>>,
        creation_date: Option<u64>,
        comment: Option<String>,
        created_by: Option<String>,
        encoding: Option<String>,
        is_private: bool,
        web_seeds: Option<Vec<String>>,
    ) -> Self {
        TorrentMetadata {
            info_hash,
            name,
            piece_length,
            pieces,
            files,
            announce,
            announce_list,
            creation_date,
            comment,
            created_by,
            encoding,
            is_private,
            web_seeds,
        }
    }

    pub fn get_info_hash(torrent: &Bencode) -> Result<[u8; 20], TorrentError> {
        let info = match torrent.as_dict().and_then(|d| d.get(&b"info".to_vec())) {
            Some(info) => Ok(info),
            None => Err(TorrentError::MissingField("info".to_string())),
        }?;

        let mut buffer = Vec::new();
        Bencode::encode(info, &mut buffer);

        let mut hasher = Sha1::new();
        hasher.update(&buffer);
        let info_hash: [u8; 20] = match hasher.finalize().try_into() {
            Ok(hash) => hash,
            Err(_) => {
                return Err(TorrentError::HashError(
                    "Failed to convert hash to array".to_string(),
                ));
            }
        };

        Ok(info_hash)
    }

    pub fn from_file(path: &Path) -> Result<TorrentMetadata, TorrentError> {
        let bytes = read(path)?;
        let (bencoded_metadata, remaining_bytes) = match Bencode::parse(&bytes) {
            Ok(md) => md,
            Err(_) => {
                return Err(TorrentError::Bencode(
                    "Failed to parse bytes to bencode!".to_string(),
                ));
            }
        };

        if remaining_bytes.len() != 0 {
            return Err(TorrentError::InvalidMetadata(
                "Extra bytes found after parsing metadata".to_string(),
            ));
        }

        let info_hash = TorrentMetadata::get_info_hash(&bencoded_metadata)?;

        let info_dict = bencoded_metadata
            .as_dict()
            .and_then(|d| d.get(&b"info".to_vec()))
            .ok_or_else(|| TorrentError::MissingField("Missing field 'info'".to_string()))?
            .as_dict()
            .ok_or_else(|| TorrentError::InvalidMetadata("Invalid field 'info'".to_string()))?;

        let name = info_dict
            .get(&b"name".to_vec())
            .ok_or_else(|| TorrentError::MissingField("Missing field 'name'".to_string()))?
            .as_string()
            .ok_or_else(|| TorrentError::InvalidMetadata("Invalid field 'name'".to_string()))?;

        let piece_length: u64 = info_dict
            .get(&b"piece length".to_vec())
            .ok_or_else(|| TorrentError::MissingField("Missing field 'piece length'".to_string()))?
            .as_int()
            .ok_or_else(|| {
                TorrentError::InvalidMetadata("Invalid field 'piece length'".to_string())
            })?
            .try_into()
            .map_err(|_| TorrentError::InvalidMetadata("Invalid piece length".to_string()))?;

        let pieces_bytes = info_dict
            .get(&b"pieces".to_vec())
            .ok_or_else(|| TorrentError::MissingField("Missing field 'pieces'".to_string()))?
            .as_string()
            .ok_or_else(|| TorrentError::InvalidMetadata("Invalid field 'pieces'".to_string()))?;

        let pieces: Vec<[u8; 20]> = pieces_bytes
            .chunks_exact(20)
            .map(|chunk| {
                let mut hash = [0u8; 20];
                hash.copy_from_slice(chunk);
                hash
            })
            .collect();

        let length_dict = info_dict.get(&b"length".to_vec());
        let files_dict = info_dict.get(&b"files".to_vec());

        if (length_dict.is_some() && files_dict.is_some())
            || (length_dict.is_none() && files_dict.is_none())
        {
            return Err(TorrentError::InvalidMetadata(
                "Torrent must contain either 'length' or 'files', but not both".to_string(),
            ));
        }

        let mut files: Vec<TorrentFile> = Vec::new();

        if length_dict.is_some() {
            let length: u64 = length_dict
                .ok_or_else(|| TorrentError::Bencode("Length invalid".to_string()))?
                .as_int()
                .ok_or_else(|| TorrentError::InvalidMetadata("Length invalid".to_string()))?
                .try_into()
                .map_err(|_| TorrentError::InvalidMetadata("Length invalid".to_string()))?;

            let path = String::from_utf8(name.to_vec())?;

            files.push(TorrentFile::new(length, path, None));
        } else {
            let files_list = files_dict
                .ok_or_else(|| TorrentError::Bencode("Invalid Files Bencode".to_string()))?
                .as_vec()
                .ok_or_else(|| TorrentError::InvalidMetadata("Invalid Files Data".to_string()))?;
            for file in files_list {
                let file_dict = file.as_dict().ok_or_else(|| {
                    TorrentError::InvalidMetadata("Invalid File Dictionary".to_string())
                })?;

                let file_length = file_dict
                    .get(&b"length".to_vec())
                    .ok_or_else(|| {
                        TorrentError::InvalidMetadata("Invalid File Length".to_string())
                    })?
                    .as_int()
                    .ok_or_else(|| {
                        TorrentError::InvalidMetadata("Invalid File Length".to_string())
                    })?
                    .try_into()
                    .map_err(|_| {
                        TorrentError::InvalidMetadata("Invalid File Length".to_string())
                    })?;

                let path = file_dict
                    .get(&b"path".to_vec())
                    .ok_or_else(|| TorrentError::InvalidMetadata("Invalid File Path".to_string()))?
                    .as_vec()
                    .ok_or_else(|| {
                        TorrentError::InvalidMetadata("Invalid File Path".to_string())
                    })?;

                let path_string: Vec<String> = path
                    .iter()
                    .map(|d| {
                        String::from_utf8(
                            d.as_string()
                                .ok_or_else(|| {
                                    TorrentError::InvalidMetadata("Invalid File Path".to_string())
                                })?
                                .to_vec(),
                        )
                        .map_err(|_| TorrentError::InvalidMetadata("Invalid path".to_string()))
                    })
                    .collect::<Result<Vec<_>, TorrentError>>()?;

                let path_str = path_string.join("/");

                files.push(TorrentFile::new(file_length, path_str, None));
            }
        }

        let metadata: TorrentMetadata = TorrentMetadata::new(
            info_hash,
            String::from_utf8(name.to_vec())?,
            piece_length,
            pieces,
            files,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            None,
        );

        Ok(metadata)
    }
}

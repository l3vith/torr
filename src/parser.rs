use std::collections::BTreeMap;

enum Bencode {
    Integer(i64),
    String(Vec<u8>),
    List(Vec<Bencode>),
    Dictionary(BTreeMap<Vec<u8>, Bencode>),
}

enum ParseError {
    UnexpectedEnd,
    ExpectedColon,
    InvalidInteger,
    InvalidStringLength,
    ExpectedTerminator,
    ExpectedInteger,
    UnknownType,
}

impl Bencode {
    pub fn parse(torrent: &[u8]) {}

    fn parse_integer(bytes: &[u8]) -> Result<(Bencode, &[u8]), ParseError> {
        if !bytes.starts_with(b"i") {
            return Err(ParseError::ExpectedInteger);
        }
        let end = bytes
            .iter()
            .position(|b| *b == b'e')
            .ok_or(ParseError::ExpectedTerminator)?;
        let num_bytes = &bytes[1..end];
        let num_str = std::str::from_utf8(num_bytes).map_err(|_| ParseError::InvalidInteger)?;
        let num = num_str
            .parse::<i64>()
            .map_err(|_| ParseError::InvalidInteger)?;
        Ok((Bencode::Integer(num), &bytes[end + 1..]))
    }

    fn parse_string(bytes: &[u8]) -> Result<(Bencode, &[u8]), ParseError> {
        let colon_pos = bytes
            .iter()
            .position(|b| *b == b':')
            .ok_or(ParseError::ExpectedColon)?;
        let length = std::str::from_utf8(&bytes[0..colon_pos])
            .map_err(|_| ParseError::InvalidStringLength)?
            .parse::<usize>()
            .map_err(|_| ParseError::InvalidStringLength)?;
        if colon_pos + 1 + length > bytes.len() {
            return Err(ParseError::InvalidStringLength);
        }
        let string = bytes[colon_pos + 1..(colon_pos + 1 + length)].to_vec();
        Ok((Bencode::String(string), &bytes[colon_pos + 1 + length..]))
    }
    
}

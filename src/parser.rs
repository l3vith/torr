use std::collections::BTreeMap;
use std::fmt;
use std::io::{Write};

#[derive(Debug)]
pub enum Bencode {
    Integer(i64),
    String(Vec<u8>),
    List(Vec<Bencode>),
    Dictionary(BTreeMap<Vec<u8>, Bencode>),
}

#[derive(Debug)]
pub enum ParseError {
    UnexpectedEnd,
    ExpectedColon,
    InvalidInteger,
    InvalidStringLength,
    ExpectedTerminator,
    ExpectedInitiator,
    ExpectedInteger,
    UnknownType,
}

impl Bencode {
    pub fn parse(bytes: &[u8]) -> Result<(Bencode, &[u8]), ParseError> {
        if bytes.is_empty() {
            return Err(ParseError::UnexpectedEnd);
        }

        match bytes[0] {
            b'i' => Bencode::parse_integer(bytes),
            b'l' => Bencode::parse_list(bytes),
            b'd' => Bencode::parse_dict(bytes),
            b'0'..=b'9' => Bencode::parse_string(bytes),
            _ => Err(ParseError::UnknownType),
        }
    }
    
    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Bencode>> {
        match self {
            Bencode::Dictionary(d) => Some(d),
            _ => None,
        }
    }
    
    pub fn as_string(&self) -> Option<&[u8]> {
        match self {
            Bencode::String(s) => Some(s),
            _ => None,
        }
    }
    
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Bencode::Integer(i) => Some(*i),
            _ => None,
        }
    }
    
    pub fn encode<W: Write>(bencode: &Bencode, writer: &mut W) -> std::io::Result<()> {
        match bencode {
            Bencode::Integer(i) => {
                writer.write_all(b"i")?;
                write!(writer, "{}", i)?;
                writer.write_all(b"e")?;
                Ok(())
            },
            Bencode::String(s) => {
                write!(writer, "{}:", s.len())?;
                writer.write_all(s)?;
                Ok(())
            },
            Bencode::List(l) => {
                writer.write_all(b"l")?;
                for item in l {
                    Bencode::encode(item, writer)?;
                }
                writer.write_all(b"e")?;
                Ok(())
            },
            Bencode::Dictionary(d) => {
                writer.write_all(b"d")?;
                for (key, value) in d {
                    Bencode::encode(&Bencode::String(key.clone()), writer)?;
                    Bencode::encode(value, writer)?;
                }
                writer.write_all(b"e")?;
                Ok(())
            }
        }
    }

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

    fn parse_list(bytes: &[u8]) -> Result<(Bencode, &[u8]), ParseError> {
        if !bytes.starts_with(b"l") {
            return Err(ParseError::ExpectedInitiator);
        }

        let mut items = Vec::new();
        let mut rest = &bytes[1..];

        loop {
            if rest.is_empty() {
                return Err(ParseError::UnexpectedEnd);
            }
            if rest[0] == b'e' {
                return Ok((Bencode::List(items), &rest[1..]));
            }
            let (value, next) = Bencode::parse(rest)?;
            items.push(value);
            rest = next;
        }
    }

    fn parse_dict(bytes: &[u8]) -> Result<(Bencode, &[u8]), ParseError> {
        if !bytes.starts_with(b"d") {
            return Err(ParseError::ExpectedInitiator);
        }

        let mut dict: BTreeMap<Vec<u8>, Bencode> = BTreeMap::new();
        let mut rest = &bytes[1..];

        loop {
            if rest.is_empty() {
                return Err(ParseError::UnexpectedEnd);
            }
            if rest[0] == b'e' {
                return Ok((Bencode::Dictionary(dict), &rest[1..]));
            }

            let (key_bencode, value_bytes) = Bencode::parse_string(rest)?;
            let key = match key_bencode {
                Bencode::String(s) => Ok(s),
                _ => Err(ParseError::UnknownType),
            }?;

            let (value, rest_bytes) = Bencode::parse(value_bytes)?;

            dict.insert(key, value);
            rest = rest_bytes;
        }
    }
}

impl fmt::Display for Bencode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bencode::Integer(i) => write!(f, "{}", i),
            Bencode::String(s) => match std::str::from_utf8(s) {
                Ok(str_val) => write!(f, "\"{}\"", str_val),
                Err(_) => write!(f, "{:?}", s), // fallback for binary strings
            },
            Bencode::List(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item)?;
                }
                write!(f, "]")
            }
            Bencode::Dictionary(dict) => {
                write!(f, "{{")?;
                for (i, (k, v)) in dict.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    let key_str = std::str::from_utf8(k).unwrap_or("<invalid>");
                    write!(f, "\"{}\": {}", key_str, v)?;
                }
                write!(f, "}}")
            }
        }
    }
}

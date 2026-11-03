//! The part of CBOR (RFC 8949) that CTAP2 speaks: integers, byte and text
//! strings, arrays, maps, booleans and null, in definite lengths only.
//!
//! Written out in CTAP2's canonical form (section 8 of the CTAP 2.1
//! specification): the shortest head for every length and integer, and a
//! map's keys sorted by their encoding, shorter first, which security
//! keys check. Read back from what a key sends, which is not trusted: no
//! floats, tags or indefinite lengths, a depth limit, and no allocation
//! larger than what is left of the input.

use crate::Error;

/// How deeply arrays and maps may nest in what a key sends; CTAP2's own
/// answers go four deep at most.
const MAX_DEPTH: usize = 16;

/// A CBOR data item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    /// A map from `(key, value)` pairs; the order is fixed when written.
    pub fn map<K: Into<Value>, I: IntoIterator<Item = (K, Value)>>(entries: I) -> Value {
        Value::Map(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Value::Int(n) if *n >= 0 => head(out, 0, n.unsigned_abs()),
            // -1 - n, which for i64::MIN is i64::MAX and does not overflow.
            Value::Int(n) => head(out, 1, (-1 - *n) as u64),
            Value::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(t) => {
                head(out, 3, t.len() as u64);
                out.extend_from_slice(t.as_bytes());
            }
            Value::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.write(out);
                }
            }
            Value::Map(entries) => {
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (k.encode(), v.encode()))
                    .collect();
                encoded.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
                head(out, 5, encoded.len() as u64);
                for (k, v) in encoded {
                    out.extend_from_slice(&k);
                    out.extend_from_slice(&v);
                }
            }
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
            Value::Null => out.push(0xf6),
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The value under `key`, when this is a map that has one.
    pub fn get(&self, key: impl Into<Value>) -> Option<&Value> {
        let key = key.into();
        match self {
            Value::Map(entries) => entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Value {
        Value::Int(n)
    }
}

impl From<&str> for Value {
    fn from(t: &str) -> Value {
        Value::Text(t.to_owned())
    }
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Value {
        Value::Bool(b)
    }
}

/// A head: the major type and the shortest form of its argument.
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Exactly one data item, with nothing after it.
pub fn decode(input: &[u8]) -> Result<Value, Error> {
    let (value, used) = decode_prefix(input)?;
    if used != input.len() {
        return Err(Error::Malformed("bytes after the CBOR item"));
    }
    Ok(value)
}

/// The data item at the start of `input`, and how many bytes it took: an
/// authenticator's data has a COSE key in the middle, with no length of
/// its own in front.
pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize), Error> {
    let mut reader = Reader { input, pos: 0 };
    let value = reader.value(0)?;
    Ok((value, reader.pos))
}

struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

const TRUNCATED: Error = Error::Malformed("truncated CBOR");

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], Error> {
        let n = usize::try_from(n).map_err(|_| TRUNCATED)?;
        if n > self.remaining() {
            return Err(TRUNCATED);
        }
        let out = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn argument(&mut self, info: u8) -> Result<u64, Error> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().expect("2 bytes"),
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().expect("4 bytes"),
            )),
            27 => u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")),
            _ => return Err(Error::Malformed("indefinite or reserved CBOR length")),
        })
    }

    /// A count of items, each at least one byte, so never more than what
    /// is left: a forged count cannot make a large allocation.
    fn count(&mut self, info: u8, per_item: u64) -> Result<usize, Error> {
        let n = self.argument(info)?;
        match n.checked_mul(per_item) {
            Some(bytes) if bytes <= self.remaining() as u64 => Ok(n as usize),
            _ => Err(TRUNCATED),
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Malformed("CBOR nested too deeply"));
        }
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        let too_big = Error::Malformed("CBOR integer out of range");
        Ok(match major {
            0 => Value::Int(i64::try_from(self.argument(info)?).map_err(|_| too_big)?),
            1 => Value::Int(-1 - i64::try_from(self.argument(info)?).map_err(|_| too_big)?),
            2 => {
                let n = self.argument(info)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.argument(info)?;
                let bytes = self.take(n)?;
                let text = core::str::from_utf8(bytes)
                    .map_err(|_| Error::Malformed("CBOR text that is not UTF-8"))?;
                Value::Text(text.to_owned())
            }
            4 => {
                let n = self.count(info, 1)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let n = self.count(info, 2)?;
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    let k = self.value(depth + 1)?;
                    let v = self.value(depth + 1)?;
                    entries.push((k, v));
                }
                Value::Map(entries)
            }
            6 => return Err(Error::Malformed("CBOR tag")),
            _ => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                _ => return Err(Error::Malformed("CBOR float or simple value")),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn integers_take_the_shortest_head() {
        // RFC 8949 appendix A.
        for (n, want) in [
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65536, "1a00010000"),
            (1_000_000_000_000, "1b000000e8d4a51000"),
            (-1, "20"),
            (-25, "3818"),
            (-1000, "3903e7"),
        ] {
            assert_eq!(Value::Int(n).encode(), hex(want), "{n}");
            assert_eq!(decode(&hex(want)).unwrap(), Value::Int(n));
        }
    }

    #[test]
    fn map_keys_are_sorted_as_ctap2_wants() {
        // A COSE key: 1, 3, -1, -2, -3, whatever order it was built in.
        let key = Value::map([
            (-3, Value::Int(0)),
            (1, Value::Int(2)),
            (-1, Value::Int(1)),
            (3, Value::Int(-25)),
            (-2, Value::Int(0)),
        ]);
        assert_eq!(key.encode(), hex("a50102033818200121002200"));
        // Text keys: shorter first, then bytewise.
        let ext = Value::map([
            ("hmac-secret", Value::Bool(true)),
            ("rk", Value::Bool(false)),
            ("credProtect", Value::Int(3)),
        ]);
        let order: Vec<String> = match decode(&ext.encode()).unwrap() {
            Value::Map(m) => m
                .into_iter()
                .map(|(k, _)| k.as_text().unwrap().to_owned())
                .collect(),
            _ => unreachable!(),
        };
        assert_eq!(order, ["rk", "credProtect", "hmac-secret"]);
    }

    #[test]
    fn a_round_trip_keeps_everything() {
        let v = Value::map([
            (1, Value::Bytes(vec![1, 2, 3])),
            (2, Value::Text("silver".into())),
            (
                3,
                Value::Array(vec![Value::Bool(true), Value::Null, Value::Int(-7)]),
            ),
        ]);
        let bytes = v.encode();
        assert_eq!(decode(&bytes).unwrap(), v);
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(decode_prefix(&longer).unwrap(), (v, bytes.len()));
        assert!(decode(&longer).is_err());
    }

    #[test]
    fn hostile_input_is_refused_without_allocating() {
        for bad in [
            "",                   // nothing
            "5a",                 // byte string, length cut off
            "5affffffff00",       // byte string longer than the input
            "9bffffffffffffffff", // array of 2^64-1 items
            "bbffffffffffffffff", // map likewise
            "9f",                 // indefinite array
            "c1",                 // tag
            "f93c00",             // half float
            "1bffffffffffffffff", // integer past i64
            "62c328",             // text that is not UTF-8
        ] {
            assert!(decode(&hex(bad)).is_err(), "{bad}");
        }
        let deep = vec![0x81; MAX_DEPTH + 2];
        assert!(decode(&deep).is_err());
    }
}

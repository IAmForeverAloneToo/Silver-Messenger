//! What passes between the client and the Windows 10 helper,
//! `silver-key.exe` (docs/design/security-key.md, section 5): the request
//! on the helper's command line, nothing secret in it, and one fixed-size
//! answer back over the pipe. Here rather than in the Windows code so that
//! it is tested everywhere.

use zeroize::Zeroizing;

use crate::Error;

/// The longest credential id carried. CTAP keys make ids of a few dozen
/// to a few hundred bytes.
pub const MAX_CREDENTIAL: usize = 1024;
/// The answer: a status byte, the index of the credential that answered
/// (four bytes, big-endian), the 32-byte secret, the credential id's
/// length (two bytes) and the id, padded.
pub const ANSWER_LEN: usize = 1 + 4 + 32 + 2 + MAX_CREDENTIAL;
/// What a pipe the client makes is called, before its random part.
pub const PIPE_PREFIX: &str = r"\\.\pipe\silver-key-";

/// What the helper is asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Make a credential and return it with its secret for `input`.
    Enroll { rp_id: String, input: Vec<u8> },
    /// The secret for whichever of `candidates` (credential id, input) the
    /// key holds.
    Secret {
        rp_id: String,
        candidates: Vec<(Vec<u8>, Vec<u8>)>,
    },
}

/// The helper's answer.
pub struct Answer {
    pub index: usize,
    pub secret: Zeroizing<[u8; 32]>,
    pub credential_id: Vec<u8>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// A relying party id as it may appear on a command line: a host name.
fn valid_rp(rp_id: &str) -> bool {
    !rp_id.is_empty()
        && rp_id.len() <= 253
        && rp_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// A pipe name the client would have made: the prefix and 32 hex digits.
pub fn valid_pipe(name: &str) -> bool {
    name.strip_prefix(PIPE_PREFIX)
        .is_some_and(|rest| rest.len() == 32 && rest.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl Request {
    /// The helper's command line for this request and `pipe`.
    pub fn to_args(&self, pipe: &str) -> Vec<String> {
        let mut args = vec!["--pipe".to_owned(), pipe.to_owned()];
        match self {
            Request::Enroll { rp_id, input } => {
                args.extend(["--rp".into(), rp_id.clone(), "--enroll".into(), hex(input)]);
            }
            Request::Secret { rp_id, candidates } => {
                args.extend(["--rp".into(), rp_id.clone()]);
                for (id, input) in candidates {
                    args.extend(["--secret".into(), format!("{}:{}", hex(id), hex(input))]);
                }
            }
        }
        args
    }

    /// The pipe and the request, read back from the helper's command line;
    /// anything else on it is refused.
    pub fn from_args(args: &[String]) -> Result<(String, Request), Error> {
        let bad = Error::Malformed("the helper's command line");
        let mut pipe = None;
        let mut rp_id = None;
        let mut enroll = None;
        let mut candidates = Vec::new();
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            let value = it
                .next()
                .ok_or(Error::Malformed("the helper's command line"))?;
            match flag.as_str() {
                "--pipe" if pipe.is_none() && valid_pipe(value) => pipe = Some(value.clone()),
                "--rp" if rp_id.is_none() && valid_rp(value) => rp_id = Some(value.clone()),
                "--enroll" if enroll.is_none() => {
                    enroll = Some(unhex(value).ok_or(Error::Malformed("the helper's input"))?);
                }
                "--secret" => {
                    let (id, input) = value
                        .split_once(':')
                        .ok_or(Error::Malformed("the helper's candidate"))?;
                    let id = unhex(id).ok_or(Error::Malformed("the helper's candidate"))?;
                    let input = unhex(input).ok_or(Error::Malformed("the helper's candidate"))?;
                    if id.is_empty() || id.len() > MAX_CREDENTIAL {
                        return Err(Error::Malformed("the helper's candidate"));
                    }
                    candidates.push((id, input));
                }
                _ => return Err(bad),
            }
        }
        let (Some(pipe), Some(rp_id)) = (pipe, rp_id) else {
            return Err(bad);
        };
        let request = match (enroll, candidates.is_empty()) {
            (Some(input), true) => Request::Enroll { rp_id, input },
            (None, false) => Request::Secret { rp_id, candidates },
            _ => return Err(bad),
        };
        Ok((pipe, request))
    }
}

/// Status bytes, and what each stands for.
const OK: u8 = 0;
const OTHER: u8 = 0xff;

fn error_of(status: u8) -> Error {
    match status {
        1 => Error::Cancelled,
        2 => Error::NoCredentials,
        3 => Error::PinBlocked,
        4 => Error::PinAuthBlocked,
        5 => Error::NotTouched,
        6 => Error::Unsupported("what Silver Messenger needs (the helper says)"),
        7 => Error::Denied,
        _ => Error::Helper,
    }
}

fn status_of(e: &Error) -> u8 {
    match e {
        Error::Cancelled => 1,
        Error::NoCredentials => 2,
        Error::PinBlocked => 3,
        Error::PinAuthBlocked => 4,
        Error::NotTouched => 5,
        Error::Unsupported(_) => 6,
        Error::Denied => 7,
        _ => OTHER,
    }
}

/// The answer to write to the pipe.
pub fn encode_answer(result: Result<Answer, Error>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; ANSWER_LEN]);
    match result {
        Ok(answer) if answer.credential_id.len() <= MAX_CREDENTIAL => {
            out[0] = OK;
            out[1..5].copy_from_slice(&(answer.index as u32).to_be_bytes());
            out[5..37].copy_from_slice(answer.secret.as_slice());
            out[37..39].copy_from_slice(&(answer.credential_id.len() as u16).to_be_bytes());
            out[39..39 + answer.credential_id.len()].copy_from_slice(&answer.credential_id);
        }
        Ok(_) => out[0] = OTHER,
        Err(e) => out[0] = status_of(&e),
    }
    out
}

/// The answer read from the pipe.
pub fn decode_answer(bytes: &[u8]) -> Result<Answer, Error> {
    if bytes.len() != ANSWER_LEN {
        return Err(Error::Malformed("the helper's answer"));
    }
    match bytes[0] {
        OK => {}
        code => return Err(error_of(code)),
    }
    let index = u32::from_be_bytes(bytes[1..5].try_into().expect("4 bytes")) as usize;
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&bytes[5..37]);
    let len = usize::from(u16::from_be_bytes([bytes[37], bytes[38]]));
    if len > MAX_CREDENTIAL {
        return Err(Error::Malformed("the helper's answer"));
    }
    Ok(Answer {
        index,
        secret,
        credential_id: bytes[39..39 + len].to_vec(),
    })
}

/// A fresh pipe name.
pub fn fresh_pipe_name() -> String {
    let mut random = [0u8; 16];
    crate::hid::random(&mut random);
    format!("{PIPE_PREFIX}{}", hex(&random))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_goes_through_the_command_line_and_back() {
        let pipe = fresh_pipe_name();
        assert!(valid_pipe(&pipe));
        for request in [
            Request::Enroll {
                rp_id: "silver-messenger.local".into(),
                input: vec![7; 32],
            },
            Request::Secret {
                rp_id: "silver-messenger.local".into(),
                candidates: vec![(vec![1, 2, 3], vec![4; 32]), (vec![9; 70], vec![5; 32])],
            },
        ] {
            let args = request.to_args(&pipe);
            assert_eq!(Request::from_args(&args).unwrap(), (pipe.clone(), request));
        }
    }

    #[test]
    fn a_command_line_the_client_would_not_write_is_refused() {
        let pipe = fresh_pipe_name();
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        for args in [
            s(&[]),
            s(&["--pipe", &pipe]),
            s(&[
                "--pipe",
                r"\\.\pipe\elsewhere",
                "--rp",
                "a",
                "--enroll",
                "00",
            ]),
            s(&["--pipe", &pipe, "--rp", "a b", "--enroll", "00"]),
            s(&["--pipe", &pipe, "--rp", "a", "--enroll", "0g"]),
            s(&[
                "--pipe", &pipe, "--rp", "a", "--enroll", "00", "--secret", "01:02",
            ]),
            s(&["--pipe", &pipe, "--rp", "a", "--secret", ":02"]),
            s(&["--pipe", &pipe, "--rp", "a", "--secret"]),
            s(&["--pipe", &pipe, "--rp", "a", "--data-dir", "x"]),
        ] {
            assert!(Request::from_args(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn an_answer_is_one_fixed_size_and_carries_what_it_should() {
        let bytes = encode_answer(Ok(Answer {
            index: 3,
            secret: Zeroizing::new([8; 32]),
            credential_id: vec![1; 48],
        }));
        assert_eq!(bytes.len(), ANSWER_LEN);
        let answer = decode_answer(&bytes).unwrap();
        assert_eq!(answer.index, 3);
        assert_eq!(*answer.secret, [8; 32]);
        assert_eq!(answer.credential_id, vec![1; 48]);

        for e in [Error::Cancelled, Error::NoCredentials, Error::PinBlocked] {
            let want = e.to_string();
            let got = decode_answer(&encode_answer(Err(e))).err().unwrap();
            assert_eq!(got.to_string(), want);
        }
        assert!(matches!(
            decode_answer(&encode_answer(Err(Error::Timeout))),
            Err(Error::Helper)
        ));
        assert!(decode_answer(&bytes[..10]).is_err());
    }
}

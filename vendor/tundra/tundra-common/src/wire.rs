use compact_str::ToCompactString;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const PROTO_VERSION: u8 = 2;
pub const ALPN_TUNNEL: &[u8] = b"calagopus-tunnel/1";

pub const MAX_FRAME_LEN: usize = 16 * 1024;
pub const DRAIN_CHUNK: usize = 256;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum ControlMsg {
    Hello {
        proto_version: u8,
        instance_id: u64,
        jwt: String,
        resume: Option<ResumeIntent>,
    },
    HelloAck {
        instance_id: u64,
        resume_accepted: bool,
    },
    ReAuth {
        jwt: String,
    },
    ReAuthAck,
    FlowOpen(FlowOpen),
    FlowUnknown {
        flow_id: u64,
    },
    DrainStart {
        flows: Vec<FlowTotal>,
        last: bool,
    },
    DrainReady {
        flows: Vec<FlowTotal>,
        last: bool,
    },
    DrainComplete,
    ResumeFlows {
        flows: Vec<u64>,
        last: bool,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct ResumeIntent {
    pub parity_even: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct FlowTotal {
    pub flow_id: u64,
    pub written: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct FlowOpen {
    pub flow_id: u64,
    pub src_server: uuid::Uuid,
    pub dst_server: uuid::Uuid,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum StreamHeader {
    Open(FlowOpen),
    Resume { flow_id: u64, half: HalfClose },
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct HalfClose {
    pub tx_done: bool,
    pub rx_done: bool,
}

impl HalfClose {
    #[inline]
    pub fn merge(self, peer: HalfClose) -> Self {
        Self {
            tx_done: self.tx_done || peer.rx_done,
            rx_done: self.rx_done || peer.tx_done,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct ResumeAck {
    pub half: HalfClose,
}

#[inline]
pub fn peek_hello_version(body: &[u8]) -> Option<u8> {
    match body {
        [0, version, ..] => Some(*version),
        _ => None,
    }
}

#[derive(Debug)]
pub enum WireError {
    Encode(compact_str::CompactString),
    Decode(compact_str::CompactString),
    FrameTooLong { len: usize },
    Truncated,
    BadVarint,
    UnknownFlags(u8),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Encode(msg) => write!(f, "postcard encode: {msg}"),
            WireError::Decode(msg) => write!(f, "postcard decode: {msg}"),
            WireError::FrameTooLong { len } => {
                write!(
                    f,
                    "frame of {len} bytes exceeds the {MAX_FRAME_LEN} byte limit"
                )
            }
            WireError::Truncated => write!(f, "truncated datagram"),
            WireError::BadVarint => write!(f, "malformed varint"),
            WireError::UnknownFlags(flags) => write!(f, "unknown datagram flags {flags:#04x}"),
        }
    }
}

impl std::error::Error for WireError {}

#[inline]
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, WireError> {
    let body =
        postcard::to_stdvec(msg).map_err(|err| WireError::Encode(err.to_compact_string()))?;
    if body.len() > MAX_FRAME_LEN {
        return Err(WireError::FrameTooLong { len: body.len() });
    }

    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);

    Ok(out)
}

#[inline]
pub fn decode_frame<T: DeserializeOwned>(body: &[u8]) -> Result<T, WireError> {
    postcard::from_bytes(body).map_err(|err| WireError::Decode(err.to_compact_string()))
}

#[inline]
pub fn frame_len(prefix: [u8; 4]) -> Result<usize, WireError> {
    let len = u32::from_le_bytes(prefix) as usize;
    if len > MAX_FRAME_LEN {
        return Err(WireError::FrameTooLong { len });
    }

    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    // encode_frame / decode_frame

    fn roundtrip(msg: &ControlMsg) {
        let framed = encode_frame(msg).unwrap();
        let len = frame_len(framed[..4].try_into().unwrap()).unwrap();
        assert_eq!(len, framed.len() - 4);
        assert_eq!(*msg, decode_frame::<ControlMsg>(&framed[4..]).unwrap());
    }

    #[test]
    fn frame_roundtrips_every_control_message() {
        roundtrip(&ControlMsg::Hello {
            proto_version: PROTO_VERSION,
            instance_id: u64::MAX,
            jwt: "a.b.c".into(),
            resume: Some(ResumeIntent { parity_even: true }),
        });
        roundtrip(&ControlMsg::Hello {
            proto_version: PROTO_VERSION,
            instance_id: 0,
            jwt: String::new(),
            resume: None,
        });
        roundtrip(&ControlMsg::HelloAck {
            instance_id: 7,
            resume_accepted: false,
        });
        roundtrip(&ControlMsg::ReAuth { jwt: String::new() });
        roundtrip(&ControlMsg::ReAuthAck);
        roundtrip(&ControlMsg::FlowOpen(FlowOpen {
            flow_id: u64::MAX,
            src_server: uuid::Uuid::from_u128(1),
            dst_server: uuid::Uuid::from_u128(2),
            dst_port: 65535,
        }));
        roundtrip(&ControlMsg::FlowUnknown { flow_id: 0 });
        roundtrip(&ControlMsg::DrainStart {
            flows: vec![FlowTotal {
                flow_id: 4,
                written: u64::MAX,
            }],
            last: true,
        });
        roundtrip(&ControlMsg::DrainReady {
            flows: Vec::new(),
            last: false,
        });
        roundtrip(&ControlMsg::DrainComplete);
        roundtrip(&ControlMsg::ResumeFlows {
            flows: vec![0, 2, 4],
            last: true,
        });
    }

    #[test]
    fn stream_header_roundtrips_and_stays_compact() {
        let h = StreamHeader::Open(FlowOpen {
            flow_id: 6,
            src_server: uuid::Uuid::from_u128(0xdead),
            dst_server: uuid::Uuid::from_u128(0xbeef),
            dst_port: 25565,
        });

        let framed = encode_frame(&h).unwrap();
        // discriminant, flow id varint, two length-prefixed uuids (1 + 16), port varint
        assert_eq!(framed.len(), 4 + 1 + 1 + 17 + 17 + 3);
        assert_eq!(h, decode_frame(&framed[4..]).unwrap());

        let resume = StreamHeader::Resume {
            flow_id: 9,
            half: HalfClose {
                tx_done: true,
                rx_done: false,
            },
        };

        let framed = encode_frame(&resume).unwrap();
        assert_eq!(resume, decode_frame(&framed[4..]).unwrap());
    }

    #[test]
    fn drain_chunk_fits_one_frame() {
        let flows: Vec<_> = (0..DRAIN_CHUNK)
            .map(|_| FlowTotal {
                flow_id: u64::MAX,
                written: u64::MAX,
            })
            .collect();

        let framed = encode_frame(&ControlMsg::DrainStart { flows, last: false }).unwrap();
        assert!(framed.len() < MAX_FRAME_LEN);

        let ids: Vec<_> = (0..DRAIN_CHUNK).map(|_| u64::MAX).collect();
        let framed = encode_frame(&ControlMsg::ResumeFlows {
            flows: ids,
            last: true,
        })
        .unwrap();
        assert!(framed.len() < MAX_FRAME_LEN);
    }

    #[test]
    fn encode_frame_writes_a_little_endian_length_prefix() {
        let framed = encode_frame(&ControlMsg::ReAuthAck).unwrap();
        assert_eq!(framed[..4], [1, 0, 0, 0]);
    }

    #[test]
    fn frame_len_rejects_an_oversized_length_prefix() {
        let huge = ((MAX_FRAME_LEN + 1) as u32).to_le_bytes();
        assert!(frame_len(huge).is_err());
        assert!(frame_len(u32::MAX.to_le_bytes()).is_err());
    }

    #[test]
    fn encode_frame_refuses_an_oversized_payload() {
        let msg = ControlMsg::ReAuth {
            jwt: "x".repeat(MAX_FRAME_LEN + 1),
        };

        let err = encode_frame(&msg).unwrap_err().to_string();
        assert!(err.contains("exceeds the"));
    }

    #[test]
    fn decode_frame_rejects_a_truncated_body() {
        let framed = encode_frame(&ControlMsg::FlowUnknown { flow_id: 7 }).unwrap();
        assert!(decode_frame::<ControlMsg>(&framed[4..framed.len() - 1]).is_err());
    }

    #[test]
    fn decode_frame_rejects_an_unknown_discriminant() {
        assert!(decode_frame::<ControlMsg>(&[250, 0, 0]).is_err());
    }

    // HalfClose

    #[test]
    fn merge_settles_a_direction_either_end_has_ended() {
        let none = HalfClose::default();
        let sender_finished = HalfClose {
            tx_done: true,
            rx_done: false,
        };
        let receiver_saw_it = HalfClose {
            tx_done: false,
            rx_done: true,
        };

        assert_eq!(none.merge(sender_finished), receiver_saw_it);
        assert_eq!(none.merge(receiver_saw_it), sender_finished);

        assert_eq!(sender_finished.merge(receiver_saw_it), sender_finished);
        assert_eq!(none.merge(none), none);
    }

    // peek_hello_version

    #[test]
    fn peek_hello_version_reads_an_older_encoding() {
        let framed = encode_frame(&ControlMsg::Hello {
            proto_version: PROTO_VERSION,
            instance_id: 1,
            jwt: "x".into(),
            resume: None,
        })
        .unwrap();

        assert_eq!(peek_hello_version(&framed[4..]), Some(PROTO_VERSION));

        // another version's encoding: same variant index, same first field, different body
        assert_eq!(peek_hello_version(&[0, 1, 0]), Some(1));

        assert_eq!(peek_hello_version(&[1, 2, 3]), None);
        assert_eq!(peek_hello_version(&[0]), None);
        assert_eq!(peek_hello_version(&[]), None);
    }
}

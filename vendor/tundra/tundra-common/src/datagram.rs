use crate::wire::WireError;

pub const FLAG_FRAG: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragHeader {
    pub group: u16,
    pub index: u8,
    pub count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramHeader {
    pub flow_id: u64,
    pub frag: Option<FragHeader>,
}

#[inline]
pub fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }

    n
}

#[inline]
pub fn put_varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }

    out.push(v as u8);
}

#[inline]
pub fn take_varint(buf: &[u8]) -> Result<(u64, &[u8]), WireError> {
    let mut value = 0u64;
    for (i, &b) in buf.iter().enumerate() {
        if i == 10 {
            return Err(WireError::BadVarint);
        }

        let shift = 7 * i;
        let chunk = u64::from(b & 0x7f);
        if chunk
            .checked_shl(shift as u32)
            .is_none_or(|c| c >> shift != chunk)
        {
            return Err(WireError::BadVarint);
        }

        value |= chunk << shift;
        if b & 0x80 == 0 {
            if i > 0 && b == 0 {
                return Err(WireError::BadVarint);
            }

            return Ok((value, buf.get(i + 1..).ok_or(WireError::Truncated)?));
        }
    }

    Err(WireError::Truncated)
}

#[inline]
pub fn header_len(flow_id: u64, fragmented: bool) -> usize {
    varint_len(flow_id) + 1 + if fragmented { 4 } else { 0 }
}

pub fn put_header(hdr: DatagramHeader, out: &mut Vec<u8>) {
    put_varint(hdr.flow_id, out);

    match hdr.frag {
        None => out.push(0),
        Some(f) => {
            out.push(FLAG_FRAG);
            out.extend_from_slice(&f.group.to_le_bytes());
            out.push(f.index);
            out.push(f.count);
        }
    }
}

pub fn parse(buf: &[u8]) -> Result<(DatagramHeader, &[u8]), WireError> {
    const KNOWN_FLAGS: u8 = FLAG_FRAG;

    let (flow_id, rest) = take_varint(buf)?;
    let (&flags, rest) = rest.split_first().ok_or(WireError::Truncated)?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(WireError::UnknownFlags(flags));
    }

    if flags & FLAG_FRAG == 0 {
        return Ok((
            DatagramHeader {
                flow_id,
                frag: None,
            },
            rest,
        ));
    }

    let Some((&[group_lo, group_hi, index, count], payload)) = rest.split_first_chunk::<4>() else {
        return Err(WireError::Truncated);
    };

    Ok((
        DatagramHeader {
            flow_id,
            frag: Some(FragHeader {
                group: u16::from_le_bytes([group_lo, group_hi]),
                index,
                count,
            }),
        },
        payload,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // varint

    #[test]
    fn varint_roundtrips_across_the_range() {
        let cases = [
            0,
            1,
            127,
            128,
            255,
            16383,
            16384,
            u32::MAX as u64,
            u64::MAX / 2,
            u64::MAX,
        ];
        for v in cases {
            let mut buf = Vec::new();
            put_varint(v, &mut buf);
            assert_eq!(buf.len(), varint_len(v));

            let (got, rest) = take_varint(&buf).unwrap();
            assert_eq!(got, v);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn varint_leaves_trailing_bytes_untouched() {
        let mut buf = Vec::new();
        put_varint(300, &mut buf);
        buf.extend_from_slice(b"tail");
        let (v, rest) = take_varint(&buf).unwrap();
        assert_eq!(v, 300);
        assert_eq!(rest, b"tail");
    }

    #[test]
    fn varint_rejects_truncated_overlong_and_non_canonical() {
        assert!(take_varint(&[]).is_err());
        assert!(take_varint(&[0x80]).is_err());
        assert!(take_varint(&[0xff; 12]).is_err());
        // 0x80 0x00 is a non-canonical encoding of zero
        assert!(take_varint(&[0x80, 0x00]).is_err());
        assert!(
            take_varint(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f]).is_err()
        );
    }

    // DatagramHeader

    #[test]
    fn plain_header_roundtrips() {
        let hdr = DatagramHeader {
            flow_id: 4242,
            frag: None,
        };

        let mut buf = Vec::new();
        put_header(hdr, &mut buf);
        buf.extend_from_slice(b"payload");
        assert_eq!(buf.len(), header_len(4242, false) + 7);

        let (got, payload) = parse(&buf).unwrap();
        assert_eq!(got, hdr);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn fragmented_header_roundtrips() {
        let hdr = DatagramHeader {
            flow_id: 1,
            frag: Some(FragHeader {
                group: 0xbeef,
                index: 3,
                count: 9,
            }),
        };

        let mut buf = Vec::new();
        put_header(hdr, &mut buf);
        buf.extend_from_slice(b"x");
        assert_eq!(buf.len(), header_len(1, true) + 1);

        let (got, payload) = parse(&buf).unwrap();
        assert_eq!(got, hdr);
        assert_eq!(payload, b"x");
    }

    #[test]
    fn empty_payload_is_representable() {
        let hdr = DatagramHeader {
            flow_id: 7,
            frag: None,
        };

        let mut buf = Vec::new();
        put_header(hdr, &mut buf);

        let (got, payload) = parse(&buf).unwrap();
        assert_eq!(got, hdr);
        assert!(payload.is_empty());
    }

    #[test]
    fn parse_rejects_truncated_and_unknown_flag_datagrams() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[1]).is_err());

        let unknown = parse(&[1, 0x02]).unwrap_err().to_string();
        assert!(unknown.contains("unknown datagram flags 0x02"));

        let truncated = parse(&[1, FLAG_FRAG, 0, 0, 0]).unwrap_err().to_string();
        assert!(truncated.contains("truncated"));
    }
}

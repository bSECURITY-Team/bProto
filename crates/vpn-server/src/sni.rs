//! ClientHello inspection for the TCP donor splice.
//!
//! A TLS 1.3 handshake binds every ClientHello byte into the transcript, so
//! the SNI of a live connection can never be modified in flight — a rewritten
//! hello makes the two sides derive different keys and the client aborts with
//! `bad record mac`. All we may do is look: `extract_sni` lifts the SNI out of
//! the first record so the splice can pick which donor edge to visit. The
//! record itself is always forwarded byte for byte.

/// Extract the SNI hostname from the first TLS record (`header + body`).
/// Returns `None` when the record is not a plaintext ClientHello or carries
/// no SNI.
#[must_use]
pub fn extract_sni(header: &[u8; 5], body: &[u8]) -> Option<String> {
    if header[0] != 0x16 {
        return None; // not a handshake record
    }
    if body.len() < 4 || body[0] != 0x01 {
        return None; // not a ClientHello
    }
    let hs_len = u32::from_be_bytes([0, body[1], body[2], body[3]]) as usize;
    if hs_len + 4 != body.len() {
        return None; // fragmented or trailing data: leave it alone
    }
    let ch = &body[4..];

    // ClientHello: version(2) random(32) sid(1+..) suites(2+..) comp(1+..) ext(2+..)
    let mut p = 2 + 32;
    p += 1 + usize::from(ch.get(p).copied().unwrap_or(u8::MAX)); // session id
    if p + 2 > ch.len() {
        return None;
    }
    let suites = u16::from_be_bytes([ch[p], ch[p + 1]]) as usize;
    p += 2 + suites;
    let comp = usize::from(*ch.get(p)?);
    p += 1 + comp;
    if p + 2 > ch.len() {
        return None;
    }
    let exts_len = u16::from_be_bytes([ch[p], ch[p + 1]]) as usize;
    let exts = ch.get(p + 2..p + 2 + exts_len)?;

    let mut off = 0;
    while off + 4 <= exts.len() {
        let (etype, elen) = (
            u16::from_be_bytes([exts[off], exts[off + 1]]),
            u16::from_be_bytes([exts[off + 2], exts[off + 3]]) as usize,
        );
        if off + 4 + elen > exts.len() {
            return None;
        }
        if etype == 0x0000 && elen >= 5 {
            // server_name_list: list_len(2) + name_type(1) + name_len(2) + name
            let list_len = u16::from_be_bytes([exts[off + 4], exts[off + 5]]) as usize;
            let name_type = exts.get(off + 6).copied().unwrap_or(0xFF);
            let name_len = u16::from_be_bytes([exts[off + 7], exts[off + 8]]) as usize;
            if name_type == 0 && list_len == elen - 2 && off + 9 + name_len <= off + 4 + elen {
                return String::from_utf8(exts[off + 9..off + 9 + name_len].to_vec()).ok();
            }
            return None; // malformed SNI: treat as absent
        }
        off += 4 + elen;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(sni: Option<&str>) -> ([u8; 5], Vec<u8>) {
        let mut body = vec![0x01, 0x00, 0x00, 0x00]; // handshake hdr, len patched below
        body.extend_from_slice(&[0x03, 0x03]); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.extend_from_slice(&[0x00]); // empty session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one suite
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        let mut exts = vec![0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]; // supported_groups
        if let Some(name) = sni {
            let n = name.as_bytes();
            let elen = 2 + 1 + 2 + n.len();
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&(elen as u16).to_be_bytes());
            exts.extend_from_slice(&((elen - 2) as u16).to_be_bytes());
            exts.extend_from_slice(&[0x00]);
            exts.extend_from_slice(&(n.len() as u16).to_be_bytes());
            exts.extend_from_slice(n);
        }
        let elen = exts.len();
        body.extend_from_slice(&(elen as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let hs_len = body.len() - 4;
        body[1..4].copy_from_slice(&(hs_len as u32).to_be_bytes()[1..]);
        let mut header = [0x16, 0x03, 0x01, 0x00, 0x00];
        header[3..5].copy_from_slice(&(body.len() as u16).to_be_bytes());
        (header, body)
    }

    #[test]
    fn lifts_the_sni_when_present() {
        let (header, body) = client_hello(Some("tesla.com"));
        assert_eq!(extract_sni(&header, &body).as_deref(), Some("tesla.com"));
    }

    #[test]
    fn reports_absent_sni() {
        let (header, body) = client_hello(None);
        assert_eq!(extract_sni(&header, &body), None);
    }

    #[test]
    fn ignores_non_handshake_records() {
        let header = [0x17u8, 0x03, 0x03, 0x00, 0x05];
        let body = [1u8, 2, 3, 4, 5];
        assert!(extract_sni(&header, &body).is_none());
    }
}

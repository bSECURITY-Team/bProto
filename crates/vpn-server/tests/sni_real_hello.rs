use vpn_server::sni::extract_sni;

/// A real openssl/curl ClientHello (captured live). The library must read it
/// and report that it carries no SNI (curl to an IP) — and must never suggest
/// modifying it, because TLS 1.3 binds the hello bytes into the transcript.
#[test]
fn reads_a_real_openssl_client_hello() {
    let raw = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/ch.bin")).unwrap();
    let rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    let header: [u8; 5] = raw[..5].try_into().unwrap();
    let body = &raw[5..5 + rec_len];
    assert_eq!(extract_sni(&header, body), None);
}

//! Regenerate the four test import links straight from the server's keys.
//! Reads psk/tag_key from a file (never hand-typed) and roundtrip-verifies
//! every URI before writing it out.
use std::time::Duration;
use vpn_core::config::{
    DonorSpec, Fingerprint, StealthLevel, TransportKind, TunnelConfig, from_hex,
    from_import_uri_with_label, to_import_uri,
};
use vpn_core::shape::ShapeConfig;

fn main() {
    let keys =
        std::fs::read_to_string("/data/data/com.termux/files/usr/tmp/opencode/keys.txt").unwrap();
    let mut lines = keys.lines();
    let psk: [u8; 32] = vpn_core::config::from_hex(lines.next().unwrap().trim())
        .unwrap()
        .try_into()
        .unwrap();
    let tag_key: [u8; 32] = vpn_core::config::from_hex(lines.next().unwrap().trim())
        .unwrap()
        .try_into()
        .unwrap();

    let base = TunnelConfig {
        server: "72.61.171.192:45001".parse().unwrap(),
        donor: DonorSpec {
            sni: "tesla.com".into(),
            ..DonorSpec::default()
        },
        psk,
        user_id: 1,
        tag_key,
        mtu: 1280,
        fingerprint: Fingerprint::Chrome112,
        stealth: StealthLevel::default(),
        handshake_timeout: Duration::from_secs(10),
        shape: ShapeConfig::default(),
        transport: TransportKind::Udp,
    };

    let variants = [
        (
            "vps-tcp",
            "72.61.171.192:45002",
            TransportKind::Tcp,
            "TCP — порт 45002 — самый стабильный",
        ),
        (
            "vps-udp",
            "72.61.171.192:45001",
            TransportKind::Udp,
            "UDP — порт 45001 — нативный, лучшая маскировка (Chrome QUIC parrot)",
        ),
        (
            "vps-auto",
            "72.61.171.192:45001",
            TransportKind::Auto,
            "AUTO — порт 45001 — сначала UDP, затем TCP-фолбэк невозможен (на 45001 нет TCP)",
        ),
        (
            "vps-auto-45002",
            "72.61.171.192:45002",
            TransportKind::Auto,
            "AUTO — порт 45002 — UDP-попытка, затем TCP; надёжнее всего",
        ),
    ];

    let mut out = String::from(
        "# bProto import links — server 72.61.171.192 (user 1, SNI tesla.com, shape chrome-quic, mtu 1280)\n# PSK/tag_key taken byte-for-byte from the VPS server.toml; every URI roundtrip-verified.\n",
    );
    for (label, server, transport, note) in variants {
        let mut cfg = base.clone();
        cfg.server = server.parse().unwrap();
        cfg.transport = transport;
        let uri = to_import_uri(&cfg, label);
        // Roundtrip: decode and compare the psk byte-for-byte.
        let (parsed, parsed_label) =
            from_import_uri_with_label(&uri).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(parsed.psk, psk, "{label}: psk mismatch");
        assert_eq!(parsed.tag_key, tag_key, "{label}: tag_key mismatch");
        assert_eq!(
            parsed.server.to_string(),
            server,
            "{label}: server mismatch"
        );
        assert_eq!(parsed_label.as_deref(), Some(label));
        out.push_str(&format!("\n### {label}: {note}\n\n{uri}\n"));
        println!("{label}: OK");
    }
    std::fs::write(".local-test/bproto-links.txt", out).unwrap();
    println!("written .local-test/bproto-links.txt");
}

use vpn_core::masquerade::{HelloParams, craft_initial_flight, inspect_client_hello};
use vpn_core::{Fingerprint, auth, crypto::KEY_LEN};

#[test]
fn real_crafted_parrot_roundtrips_through_inspect() {
    let psk = [0x22u8; KEY_LEN];
    let tag_key = [0x11u8; KEY_LEN];
    let user = 1u64;
    let tag = auth::compute_tag(&tag_key, user);
    let random = [0x5Au8; 32];
    let eph = vpn_core::crypto::KeyPair::generate();
    let x25519 = eph.public_bytes();
    let params = HelloParams {
        sni: "tesla.com".into(),
        alpn: vec!["h3".into()],
        fingerprint: Fingerprint::Chrome112,
        session_id: auth::derive_session_id(&psk, &tag, &random, &x25519, vpn_core::unix_now_secs()),
        client_random: random,
        x25519_pub: x25519,
    };
    let parrot = craft_initial_flight(&params, 1251).expect("craft");
    println!("parrot len = {}", parrot.len());
    match inspect_client_hello(&parrot) {
        Ok(h) => {
            println!("OK: sid={:?} sni={:?}", h.session_id.map(|s| hex(s)), h.sni);
            assert_eq!(h.session_id, Some(params.session_id));
        }
        Err(e) => panic!("inspect failed: {e}"),
    }
}

fn hex(b: [u8; 32]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

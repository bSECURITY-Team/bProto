//! The Android datapath, exercised on Linux.
//!
//! `pump` is the one piece of the JNI tier a host test cannot reach through the
//! JNI API — there is no JVM here. What we *can* do is hand it the same two
//! things Android hands it: a live tunnel and a bidirectional datagram
//! descriptor. `socketpair(2)` is an honest stand-in for the tun descriptor, so
//! this test proves the real property — packets cross both ways between the
//! descriptor and the server — instead of a mock of it.

use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use vpn_core::server::{ServerNode, ServerParams};
use vpn_core::tags::TagTable;
use vpn_core::{DonorSpec, Fingerprint, IpPool, MAX_DATAGRAM, StealthLevel, TunnelConfig};

use super::{current_stop, run_pump};
use crate::{BprotoTunnel, bproto_assigned_ip, bproto_connect, bproto_free};

const TAG_KEY: [u8; 32] = [0x22; 32];
const PSK: [u8; 32] = [0x11; 32];
const USER: u64 = 42;

/// The server side of the link, plus the channel of packets aimed at its TUN.
struct Harness {
    node: Arc<ServerNode>,
    addr: SocketAddr,
    to_tun: mpsc::Receiver<Vec<u8>>,
}

fn start_server(rt: &tokio::runtime::Runtime) -> Harness {
    let mut table = TagTable::new();
    table.insert(&TAG_KEY, USER, PSK);
    let tags = Arc::new(RwLock::new(table));
    let pool = IpPool::new("10.66.0.0".parse().unwrap(), 24);

    let (sock, addr) = rt
        .block_on(async {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            let addr = sock.local_addr()?;
            Ok::<_, std::io::Error>((Arc::new(sock), addr))
        })
        .expect("bind loopback");
    let node = Arc::new(ServerNode::new(
        Arc::clone(&sock),
        tags,
        pool,
        ServerParams::default(),
    ));

    let (to_tun_tx, to_tun) = mpsc::channel::<Vec<u8>>(1024);
    let reader = Arc::clone(&node);
    rt.spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM + 32];
        loop {
            let Ok((n, from)) = reader.socket().recv_from(&mut buf).await else {
                break;
            };
            if let Ok(Some(pkt)) = reader.handle(&buf[..n], from, 0, None).await {
                let _ = to_tun_tx.send(pkt).await;
            }
        }
    });

    Harness { node, addr, to_tun }
}

fn client_config(server: SocketAddr) -> TunnelConfig {
    TunnelConfig {
        server,
        donor: DonorSpec::default(),
        psk: PSK,
        user_id: USER,
        tag_key: TAG_KEY,
        mtu: 1280,
        fingerprint: Fingerprint::Chrome112,
        stealth: StealthLevel::Off,
        handshake_timeout: Duration::from_secs(3),
        shape: vpn_core::shape::ShapeConfig::default(),
        transport: vpn_core::TransportKind::Udp,
    }
}

/// An IPv4/UDP packet with the given endpoints and a marker byte.
fn ip_packet(src: [u8; 4], dst: [u8; 4], marker: u8) -> Vec<u8> {
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x45;
    pkt[9] = 17; // UDP
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..24].copy_from_slice(&src);
    pkt[47] = marker;
    pkt
}

/// The tunnel handle, moved onto the pump thread. Raw pointers are not `Send`;
/// this one is only ever touched by the thread it is moved to.
struct Handle(*mut BprotoTunnel);

// SAFETY: the handle is created on the test thread, moved exactly once into the
// pump thread, and freed there after `pump` returns.
unsafe impl Send for Handle {}

impl Handle {
    /// Borrowed accessor: keeps closure capture at the whole-struct level, so
    /// the closure keeps `Handle`'s `Send` rather than the raw pointer's lack
    /// of it.
    fn get(&self) -> *mut BprotoTunnel {
        self.0
    }
}

fn socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: `fds` is a valid two-element array.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(
        rc,
        0,
        "socketpair failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: both descriptors are fresh and ownership transfers here.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn write_packet(fd: RawFd, packet: &[u8]) {
    // SAFETY: `packet` is readable for its length and `fd` is ours.
    let n = unsafe { libc::write(fd, packet.as_ptr().cast(), packet.len()) };
    assert_eq!(n as usize, packet.len(), "short write");
}

/// Read one datagram with a deadline, so a broken datapath fails the test
/// instead of hanging the suite.
fn read_packet(fd: RawFd, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 65_536];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, left.as_millis() as libc::c_int) };
        if rc <= 0 {
            return None;
        }
        // SAFETY: `buf` is writable for its full length and `fd` is ours.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            buf.truncate(n as usize);
            return Some(buf);
        }
    }
}

/// The property the Android client depends on: a packet written to the tun
/// descriptor reaches the server, and a packet the server sends towards the
/// leased address comes back out of the descriptor.
#[test]
fn pump_moves_packets_both_ways() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let mut harness = start_server(&rt);

    let json = serde_json::to_string(&client_config(harness.addr)).expect("config serializes");
    let cjson = std::ffi::CString::new(json).expect("no NUL in the config");
    // SAFETY: valid NUL-terminated string.
    let handle = unsafe { bproto_connect(cjson.as_ptr()) };
    assert!(!handle.is_null(), "handshake failed");

    // Exactly what the Kotlin service feeds to Builder.addAddress().
    let mut octets = [0u8; 4];
    // SAFETY: `octets` is 4 writable bytes and the handle is live.
    assert_eq!(
        unsafe { bproto_assigned_ip(handle, octets.as_mut_ptr()) },
        0
    );
    let client_ip = Ipv4Addr::from(octets);
    assert_eq!(client_ip.to_string(), "10.66.0.2");

    let (tun_end, app_end) = socketpair();
    let tun_fd = tun_end.as_raw_fd();
    let app_fd = app_end.as_raw_fd();

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let wrapped = Handle(handle);
    let pump_thread = std::thread::spawn(move || {
        // Hold the descriptor open for the whole pump call.
        let _keep = tun_end;
        let rc = run_pump(wrapped.get(), tun_fd);
        // SAFETY: `pump` has returned; nothing else references the handle.
        unsafe { bproto_free(wrapped.get()) };
        let _ = done_tx.send(rc);
    });

    // Uplink: descriptor -> server TUN.
    let up = ip_packet([10, 66, 0, 2], [10, 66, 0, 1], 0xA1);
    write_packet(app_fd, &up);
    let arrived = rt
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(2), harness.to_tun.recv()).await
        })
        .expect("the server must deliver within 2s")
        .expect("channel open");
    assert_eq!(arrived, up, "the packet must arrive unmodified");

    // One oversized IPv4 packet must be dropped and logged, not kill the pump
    // (the Linux CLI has always continued here). A following valid packet has
    // to reach the server unchanged.
    let mut oversized = ip_packet([10, 66, 0, 2], [10, 66, 0, 1], 0xA9);
    oversized.resize(2_000, 0xA9);
    write_packet(app_fd, &oversized);
    let up2 = ip_packet([10, 66, 0, 2], [10, 66, 0, 1], 0xA2);
    write_packet(app_fd, &up2);
    let arrived2 = rt
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(2), harness.to_tun.recv()).await
        })
        .expect("the server must deliver the second packet within 2s")
        .expect("channel open");
    assert_eq!(arrived2, up2, "pump must survive an oversized packet");

    // Captured IPv6 must come back as an ICMPv6 error, not disappear into a
    // black hole with no route and no RST.
    let v6_src = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];
    let v6_dst = [0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    write_packet(app_fd, &ipv6_tcp(v6_src, v6_dst));
    let icmp = read_packet(app_fd, Duration::from_secs(2))
        .expect("captured IPv6 must produce an immediate ICMPv6 error");
    assert_eq!(icmp[0] >> 4, 6, "the reply is IPv6");
    assert_eq!(icmp[40], 1, "destination unreachable");
    assert_eq!(icmp[41], 0, "no route to destination");
    assert!(icmpv6_checksum_is_valid(&icmp));

    // Downlink: server -> descriptor.
    let down = ip_packet([1, 1, 1, 1], [10, 66, 0, 2], 0xB2);
    let sent = rt
        .block_on(harness.node.seal_outbound(client_ip, &down, 0))
        .expect("sealing outbound must work");
    assert!(sent, "the leased address must be routable");
    let got =
        read_packet(app_fd, Duration::from_secs(2)).expect("the descriptor must receive within 2s");
    assert_eq!(got, down, "the packet must arrive unmodified");

    // Stop: the same signal the JNI `stop()` entry point raises.
    current_stop().notify_one();
    let rc = done_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("pump must return after stop()");
    assert!(rc.is_ok(), "clean stop expected, got {rc:?}");
    pump_thread.join().expect("pump thread must not panic");
}

/// A minimal IPv6 + TCP packet, the shape Android feeds the tun when `::/0`
/// is captured and an app tries an AAAA address first.
fn ipv6_tcp(src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    let mut p = vec![0u8; 60];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&20u16.to_be_bytes());
    p[6] = 6; // TCP
    p[7] = 64;
    p[8..24].copy_from_slice(&src);
    p[24..40].copy_from_slice(&dst);
    p[40..42].copy_from_slice(&40_000u16.to_be_bytes());
    p[42..44].copy_from_slice(&443u16.to_be_bytes());
    p[53] = 0x02; // SYN
    p
}

/// The ICMPv6 error checksum covers the IPv6 pseudo-header as well.
fn icmpv6_checksum_is_valid(reply: &[u8]) -> bool {
    let mut input = Vec::new();
    input.extend_from_slice(&reply[8..24]); // src of the reply
    input.extend_from_slice(&reply[24..40]); // dst of the reply
    input.extend_from_slice(&((reply.len() - 40) as u32).to_be_bytes());
    input.extend_from_slice(&[0, 0, 0, 58]);
    input.extend_from_slice(&reply[40..]);
    super::internet_checksum(&input) == 0
}

#[test]
fn captured_ipv6_is_rejected_with_a_valid_icmpv6_error() {
    let src = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];
    let dst = [
        0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let original = ipv6_tcp(src, dst);
    let reply = super::icmpv6_no_route(&original).expect("a TCPv6 packet must be answered");
    assert_eq!(reply[0] >> 4, 6, "the reply is an IPv6 packet");
    assert_eq!(reply[6], 58, "next header is ICMPv6");
    assert_eq!(&reply[8..24], &super::V6_GATEWAY[..]);
    assert_eq!(
        &reply[24..40],
        &src[..],
        "the error goes back to the sender"
    );
    assert_eq!(reply[40], 1, "destination unreachable");
    assert_eq!(reply[41], 0, "no route to destination");
    assert_eq!(&reply[48..], &original[..], "the whole packet is quoted");
    assert!(
        icmpv6_checksum_is_valid(&reply),
        "ICMPv6 checksum must verify"
    );
}

#[test]
fn icmpv6_errors_are_not_sent_for_multicast_nd_or_ipv4() {
    let src = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];
    let dst = [
        0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    // Multicast destination (neighbour solicitation) is dropped silently.
    let mut nd = ipv6_tcp(src, dst);
    nd[24] = 0xff;
    nd[6] = 58;
    nd[40] = 135;
    assert!(super::icmpv6_no_route(&nd).is_none());
    // Unspecified source (DAD) is dropped silently.
    let mut dad = ipv6_tcp(src, dst);
    dad[8..24].fill(0);
    assert!(super::icmpv6_no_route(&dad).is_none());
    // ICMPv6 errors must never trigger another error (RFC 4443 §2.4).
    let mut err = ipv6_tcp(src, dst);
    err[6] = 58;
    err[40] = 1;
    assert!(super::icmpv6_no_route(&err).is_none());
    // An IPv4 packet never goes down the v6 path, and a short packet is safe.
    let v4 = ip_packet([10, 66, 0, 2], [1, 1, 1, 1], 0xA1);
    assert!(super::icmpv6_no_route(&v4).is_none());
    assert!(super::icmpv6_no_route(&[0x60, 0, 0]).is_none());
}

#[test]
fn long_ipv6_packets_are_quoted_within_a_safe_size() {
    let src = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];
    let dst = [
        0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let mut original = ipv6_tcp(src, dst);
    original.resize(10_000, 0xAB);
    let payload_len = (original.len() - 40) as u16;
    original[4..6].copy_from_slice(&payload_len.to_be_bytes());
    let reply = super::icmpv6_no_route(&original).expect("long packet is still answered");
    assert_eq!(reply.len(), 40 + 8 + super::ICMPV6_QUOTE);
    assert!(reply.len() <= 1251, "must fit the Android tun MTU");
    assert!(icmpv6_checksum_is_valid(&reply));
}

#[test]
fn icmpv6_error_walks_a_hop_by_hop_header() {
    let src = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];
    let dst = [0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    let mut original = ipv6_tcp(src, dst);
    // A hop-by-hop options header (8 bytes) followed by the TCP header.
    original[6] = 0;
    original.insert(40, 6); // next header = TCP
    original.insert(41, 0); // Hdr Ext Len = 0 => 8 bytes
    original.resize(40 + 8 + 20 + 2, 0);
    original[48] = 0x02; // SYN, so the quoted TCP header is meaningful
    let reply =
        super::icmpv6_no_route(&original).expect("TCP behind hop-by-hop options must be answered");
    assert_eq!(reply[40], 1);
    assert!(icmpv6_checksum_is_valid(&reply));
}

//! Server-side session node.
//!
//! [`ServerNode`] is the protocol half of the server: it verifies handshakes,
//! leases tunnel addresses, decrypts inbound datagrams into IP packets for the
//! TUN, and seals outbound IP packets to the right peer. The TUN device and the
//! NAT ruleset live in the binary; everything here is testable without root.
//!
//! Concurrency contract: `handle`, `seal_*` and `tick` take `&self` and lock
//! internally, but the server drives them from a *single* receive loop. They are
//! safe to call concurrently (they serialise), just not parallel in this design —
//! which is what keeps per-session state plain fields instead of another layer of
//! locks.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::ack::{AckRanges, RttEstimator, SentPackets};
use crate::auth::TAG_LEN;
use crate::congestion::Cubic;
use crate::crypto::KeyPair;
use crate::error::{Error, Result};
use crate::frame::{self, FrameType};
use crate::handshake;
use crate::ip;
use crate::packet::{self, Header};
use crate::pool::IpPool;
use crate::session::{Opened, Session, unix_now_secs};
use crate::tags::{TagTable, credential_id};
use crate::transport::udp;

/// How many received packets trigger an immediate ACK.
const ACK_EVERY: u64 = 8;

/// Tunables for one server node.
#[derive(Debug, Clone)]
pub struct ServerParams {
    /// Tunnel MTU; must match the clients.
    pub mtu: usize,
    /// Send a keepalive probe after this much inbound silence.
    pub keepalive: Duration,
    /// Evict a session after this much inbound silence.
    pub idle_timeout: Duration,
    /// Refuse new handshakes above this many live sessions.
    pub max_sessions: usize,
    /// Opening-flight shape for server-sent datagrams (HELLO_ACK, probes).
    pub shape: crate::shape::ShapeProfile,
}

impl Default for ServerParams {
    fn default() -> Self {
        Self {
            mtu: packet::TUNNEL_MTU,
            keepalive: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(45),
            max_sessions: 4096,
            shape: crate::shape::ShapeProfile::default(),
        }
    }
}

/// Counters reported to the panel / admin API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerStats {
    /// Live sessions.
    pub sessions: usize,
    /// Successful handshakes.
    pub handshakes: u64,
    /// Handshakes that failed verification (active probing / wrong keys).
    pub rejected_handshakes: u64,
    /// Datagrams whose session tag matched no live session.
    pub unknown_tags: u64,
    /// Datagrams dropped at the congestion window.
    pub congestion_drops: u64,
}

#[derive(Debug, Default)]
struct Counters {
    handshakes: AtomicU64,
    rejected_handshakes: AtomicU64,
    unknown_tags: AtomicU64,
    congestion_drops: AtomicU64,
}

#[derive(Debug)]
struct ServerSession {
    sess: Session,
    peer: SocketAddr,
    /// TCP egress for the session, when the client connected over the TCP
    /// transport. Replies and data frames go into this channel (framed by the
    /// per-connection writer task); `None` means the UDP socket.
    tcp: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    user_id: u64,
    credential: [u8; 32],
    tag: [u8; TAG_LEN],
    ip: Ipv4Addr,
    ack: AckRanges,
    pending: u64,
    last_rx_us: u64,
    /// When the next keepalive probe may go out (µs, same clock as `now_us`).
    /// Zero means "armed as soon as the keepalive threshold is crossed".
    next_ping_us: u64,
    /// Current probe spacing, doubling after every unanswered probe. Firefox's
    /// server side effectively probes with exponential backoff, not a fixed
    /// period — this mirrors that and kills the 20 ms probe storm we had.
    ping_backoff_us: u64,
    rtt: RttEstimator,
    cc: Cubic,
    sent: SentPackets,
}

#[derive(Debug, Default)]
struct Inner {
    sessions: HashMap<u32, ServerSession>,
    routes: HashMap<Ipv4Addr, u32>,
    /// Dedup of verified CLEAN HELLOs: the Firefox-shaped opening sends the
    /// same datagram twice ~0.2 ms apart (and retransmits every 500 ms when
    /// unacked). All copies must complete into ONE session; without the cache
    /// each copy would mint a fresh key set and rotate the previous one away
    /// under the client.
    handshakes: HashMap<([u8; TAG_LEN], [u8; 32]), CachedHello>,
}

/// A completed handshake kept for repeat deliveries of the same HELLO.
#[derive(Debug)]
struct CachedHello {
    /// Used to preserve retransmission dedup for unchanged credentials on reload.
    credential: [u8; 32],
    /// The exact HELLO_ACK datagram to resend (byte-identical).
    ack: Vec<u8>,
    /// Absolute micros after which the entry is stale.
    expires_us: u64,
}

/// First keepalive probe spacing.
const PING_BACKOFF_BASE_US: u64 = 1_000_000;
/// Probe spacing never exceeds this; also an implicit upper probe rate.
const PING_BACKOFF_MAX_US: u64 = 30_000_000;
/// How long a completed handshake may be re-delivered: ±1 time window skew on
/// top of the label window means replays stay valid for the client's retries.
const HELLO_CACHE_TTL_US: u64 = 600_000_000;
/// Upper bound of remembered completed handshakes (memory guard).
const HELLO_CACHE_MAX: usize = 1024;

/// The server protocol node.
#[derive(Debug)]
pub struct ServerNode {
    sock: std::sync::Arc<UdpSocket>,
    tags: std::sync::Arc<RwLock<TagTable>>,
    pool: Mutex<IpPool>,
    inner: Mutex<Inner>,
    params: ServerParams,
    counters: Counters,
}

impl ServerNode {
    /// Atomically replace authorization and evict revoked sessions. Unchanged
    /// credentials keep keys, packet counters, replay windows and IP leases.
    /// Lock order is inner -> pool -> tags, also used by handshake/teardown.
    pub async fn replace_tags(&self, mut replacement: TagTable) -> Result<usize> {
        let mut inner = self.inner.lock().await;
        let mut pool = self.pool.lock().await;
        let mut current = self
            .tags
            .write()
            .map_err(|_| Error::Config("tag table poisoned".into()))?;
        let revoked: Vec<u32> = inner
            .sessions
            .iter()
            .filter(|(_, s)| !replacement.contains_credential(&s.tag, &s.credential))
            .map(|(tag, _)| *tag)
            .collect();
        for tag in &revoked {
            if let Some(s) = inner.sessions.remove(tag) {
                inner.routes.remove(&s.ip);
                pool.release(s.ip);
            }
        }
        // Preserve dedup for unchanged credentials: clearing it would allow a
        // delayed HELLO to replace a surviving session and break live traffic.
        inner
            .handshakes
            .retain(|(tag, _), cached| replacement.contains_credential(tag, &cached.credential));
        for s in inner.sessions.values() {
            replacement.bind_address(&s.tag, s.ip);
        }
        *current = replacement;
        Ok(revoked.len())
    }

    /// Wrap an already-bound socket and a tag table.
    #[must_use]
    pub fn new(
        sock: std::sync::Arc<UdpSocket>,
        tags: std::sync::Arc<RwLock<TagTable>>,
        pool: IpPool,
        params: ServerParams,
    ) -> Self {
        Self {
            sock,
            tags,
            pool: Mutex::new(pool),
            inner: Mutex::new(Inner::default()),
            params,
            counters: Counters::default(),
        }
    }

    /// Local address the socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.sock
            .local_addr()
            .map_err(|e| Error::Transport(e.to_string()))
    }

    /// The shared UDP socket. The server binary owns the receive loop; this
    /// accessor lets it (and tests) drive the node from outside.
    #[must_use]
    pub fn socket(&self) -> std::sync::Arc<UdpSocket> {
        std::sync::Arc::clone(&self.sock)
    }

    /// Snapshot of the server counters.
    pub async fn stats(&self) -> ServerStats {
        let inner = self.inner.lock().await;
        ServerStats {
            sessions: inner.sessions.len(),
            handshakes: self.counters.handshakes.load(Ordering::Relaxed),
            rejected_handshakes: self.counters.rejected_handshakes.load(Ordering::Relaxed),
            unknown_tags: self.counters.unknown_tags.load(Ordering::Relaxed),
            congestion_drops: self.counters.congestion_drops.load(Ordering::Relaxed),
        }
    }

    /// Handle one datagram. Returns a packet to write to the TUN, if any.
    ///
    /// Replies (handshake ACK, in-session ACK, PONG) are sent from here. `tcp`
    /// carries the datagram's return path when it arrived over the TCP
    /// transport; pass `None` for the UDP socket.
    pub async fn handle(
        &self,
        datagram: &[u8],
        from: SocketAddr,
        now_us: u64,
        tcp: Option<&tokio::sync::mpsc::Sender<Vec<u8>>>,
    ) -> Result<Option<Vec<u8>>> {
        let Ok(header) = Header::decode(datagram) else {
            return Ok(None);
        };
        if header.is_control() {
            return self.handle_handshake(datagram, from, now_us, tcp).await;
        }

        let tag = header.session_tag;
        let mut inner = self.inner.lock().await;
        let close_requested;
        {
            let Some(s) = inner.sessions.get_mut(&tag) else {
                // Borrow ends here so `flush_ack`/removal below cannot double-lock.
                drop(inner);
                self.counters.unknown_tags.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            };
            // Authenticate and reject replays before accepting a new return
            // path or refreshing liveness. The visible session tag alone is
            // not proof that a packet came from this client.
            let Ok((pn, opened)) = s.sess.open(datagram).await else {
                return Ok(None);
            };
            s.peer = from;
            s.tcp = tcp.cloned();
            s.last_rx_us = now_us;
            s.ping_backoff_us = PING_BACKOFF_BASE_US;
            s.next_ping_us = 0;

            s.ack.insert(pn);
            s.pending += 1;
            if s.pending >= ACK_EVERY {
                flush_ack(s, &self.sock).await;
            }

            match opened {
                Opened::Ip(pkt) => return Ok(Some(pkt)),
                Opened::Control(frame_bytes) => {
                    close_requested = handle_control(s, &frame_bytes, now_us, &self.sock).await;
                }
                Opened::Keepalive => close_requested = false,
            }
        }

        if close_requested {
            // The client said goodbye: acknowledge the Close and tear the
            // session down immediately instead of waiting for the idle
            // timeout. No further keepalive storm after the client left.
            let ip;
            {
                let Some(s) = inner.sessions.get_mut(&tag) else {
                    return Ok(None);
                };
                flush_ack(s, &self.sock).await;
                ip = s.ip;
            }
            inner.sessions.remove(&tag);
            inner.routes.remove(&ip);
            let mut pool = self.pool.lock().await;
            pool.release(ip);
            if let Ok(mut t) = self.tags.write() {
                t.release_address(ip);
            }
            tracing::debug!(session_tag = tag, %ip, "client closed session");
        }
        Ok(None)
    }

    /// Seal and send one outbound IP packet, routing on its destination address.
    /// Returns `true` when a session accepted it.
    pub async fn seal_packet(&self, ip_packet: &[u8], now_us: u64) -> Result<bool> {
        let Some(dst) = ip::dst_ipv4(ip_packet) else {
            return Ok(false);
        };
        self.seal_outbound(dst, ip_packet, now_us).await
    }

    /// Seal and send one outbound IP packet to the session that owns `dst`.
    pub async fn seal_outbound(
        &self,
        dst: Ipv4Addr,
        ip_packet: &[u8],
        now_us: u64,
    ) -> Result<bool> {
        if ip_packet.len() > self.params.mtu {
            return Err(Error::PayloadTooLarge(ip_packet.len(), self.params.mtu));
        }
        let mut inner = self.inner.lock().await;
        let Some(&tag) = inner.routes.get(&dst) else {
            return Ok(false);
        };
        let Some(s) = inner.sessions.get_mut(&tag) else {
            inner.routes.remove(&dst);
            return Ok(false);
        };
        if !s.cc.can_send(s.sent.bytes_in_flight()) {
            self.counters
                .congestion_drops
                .fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        let (pn, datagram) = s.sess.seal_ip(ip_packet)?;
        s.sent.on_sent(pn, now_us, datagram.len() as u64);
        deliver(s, &self.sock, &datagram).await;
        Ok(true)
    }

    /// Periodic maintenance: flush ACKs, probe idle sessions, detect loss by
    /// timeout, evict dead sessions and release their addresses.
    pub async fn tick(&self, now_us: u64) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let keepalive_us = self.params.keepalive.as_micros() as u64;
        let idle_us = self.params.idle_timeout.as_micros() as u64;
        let mut expired: Vec<(u32, Ipv4Addr, [u8; TAG_LEN])> = Vec::new();

        for (&tag, s) in inner.sessions.iter_mut() {
            if s.pending > 0 {
                flush_ack(s, &self.sock).await;
            }
            let idle = now_us.saturating_sub(s.last_rx_us);
            if idle >= idle_us {
                expired.push((tag, s.ip, s.tag));
                continue;
            }
            // Probe an idle session with exponential backoff: the first probe
            // goes out after `params.keepalive` of silence, then the spacing
            // doubles 1 s → 2 s → 4 s … capped at 30 s. Any inbound datagram
            // (client ACKs included) resets the schedule. The probe is padded
            // into the Firefox control-size band, so the keepalive cannot be
            // picked out of the traffic by its 30-byte footprint either.
            if idle >= keepalive_us && now_us >= s.next_ping_us {
                if let Ok((_, datagram)) = s
                    .sess
                    .seal_control_padded(&frame::simple(FrameType::Ping), control_size())
                {
                    deliver(s, &self.sock, &datagram).await;
                }
                s.ping_backoff_us = (s.ping_backoff_us * 2).min(PING_BACKOFF_MAX_US);
                s.next_ping_us = now_us + s.ping_backoff_us;
            }
            let pto = s.rtt.pto();
            if !s.sent.timed_out(now_us, pto).is_empty() {
                s.cc.on_loss(now_us);
            }
        }

        if !expired.is_empty() {
            let mut pool = self.pool.lock().await;
            for (tag, ip, _table_tag) in expired {
                tracing::info!(session_tag = tag, %ip, "session expired after idle timeout");
                inner.sessions.remove(&tag);
                inner.routes.remove(&ip);
                pool.release(ip);
                if let Ok(mut t) = self.tags.write() {
                    t.release_address(ip);
                }
            }
        }
        Ok(())
    }

    /// Send an out-of-session datagram (handshake ACK) to the peer's return
    /// path: the TCP writer channel when the HELLO arrived over TCP, else the
    /// shared UDP socket.
    async fn reply(
        &self,
        from: SocketAddr,
        tcp: Option<&tokio::sync::mpsc::Sender<Vec<u8>>>,
        datagram: &[u8],
    ) -> Result<()> {
        if let Some(tx) = tcp {
            return tx
                .send(datagram.to_vec())
                .await
                .map_err(|_| Error::Transport("tcp sink closed".into()));
        }
        udp::send(&self.sock, datagram, from).await
    }

    async fn handle_handshake(
        &self,
        datagram: &[u8],
        from: SocketAddr,
        now_us: u64,
        tcp: Option<&tokio::sync::mpsc::Sender<Vec<u8>>>,
    ) -> Result<Option<Vec<u8>>> {
        // Serialize authorization with live snapshot replacement. Never verify
        // against an old table and insert a session after its revocation.
        let mut inner = self.inner.lock().await;
        let verified = {
            let tags = self
                .tags
                .read()
                .map_err(|_| Error::Config("tag table poisoned".into()))?;
            handshake::verify(&tags, datagram, unix_now_secs())
        };
        let Ok(verified) = verified else {
            // Not ours: an active prober, a replayed HELLO, or a wrong key.
            self.counters
                .rejected_handshakes
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };

        let mut pool = self.pool.lock().await;

        // Repeat delivery of an already-completed handshake: answer with the
        // byte-identical HELLO_ACK and create nothing.
        let key = (verified.tag, verified.client_random);
        let mut replay = None;
        if let Some(cached) = inner.handshakes.get(&key) {
            if now_us < cached.expires_us {
                replay = Some(cached.ack.clone());
            } else {
                inner.handshakes.remove(&key);
            }
        }
        if let Some(ack) = replay {
            drop(pool);
            drop(inner);
            self.reply(from, tcp, &ack).await?;
            return Ok(None);
        }

        // Replacing a user's session is the normal reconnect path: reuse nothing
        // but release the old address so the pool does not leak.
        let stale: Vec<u32> = inner
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.user_id == verified.user_id && s.credential == credential_id(&verified.psk)
            })
            .map(|(&t, _)| t)
            .collect();
        for tag in stale {
            if let Some(old) = inner.sessions.remove(&tag) {
                inner.routes.remove(&old.ip);
                pool.release(old.ip);
            }
        }

        if inner.sessions.len() >= self.params.max_sessions {
            return Err(Error::Transport("session limit reached".into()));
        }
        let Some(ip) = pool.allocate() else {
            return Err(Error::Transport("address pool exhausted".into()));
        };

        let eph = KeyPair::generate();
        let (ack_datagram, keys, session_tag) =
            handshake::respond(&verified, &eph, ip, &self.params.shape)?;

        // A tag collision would alias two sessions; drop the older one.
        if let Some(old) = inner.sessions.remove(&session_tag) {
            inner.routes.remove(&old.ip);
            pool.release(old.ip);
        }

        let session = Session::new(keys, session_tag, self.params.mtu);
        inner.routes.insert(ip, session_tag);
        inner.sessions.insert(
            session_tag,
            ServerSession {
                sess: session,
                peer: from,
                tcp: tcp.cloned(),
                user_id: verified.user_id,
                credential: credential_id(&verified.psk),
                tag: verified.tag,
                ip,
                ack: AckRanges::new(),
                pending: 0,
                last_rx_us: now_us,
                next_ping_us: 0,
                ping_backoff_us: PING_BACKOFF_BASE_US,
                rtt: RttEstimator::default(),
                cc: Cubic::new(self.params.mtu as u32),
                sent: SentPackets::default(),
            },
        );
        if let Ok(mut t) = self.tags.write() {
            // Rebuild any leases removed by reconnect or session-tag collision.
            let live = inner.sessions.values().map(|s| s.ip).collect::<Vec<_>>();
            for old in t.leased_ips() {
                if !live.contains(&old) {
                    t.release_address(old);
                }
            }
            t.bind_address(&verified.tag, ip);
        }
        drop(pool);

        // Remember this HelloAck so duplicate HELLOs (the anti-loss double
        // Initial and 500 ms retransmits) get the same answer, not a key
        // rotation. Cap the cache to bound memory.
        {
            while inner.handshakes.len() >= HELLO_CACHE_MAX {
                let Some(&victim) = inner.handshakes.keys().next() else {
                    break;
                };
                inner.handshakes.remove(&victim);
            }
            inner.handshakes.insert(
                (verified.tag, verified.client_random),
                CachedHello {
                    credential: credential_id(&verified.psk),
                    ack: ack_datagram.clone(),
                    expires_us: now_us + HELLO_CACHE_TTL_US,
                },
            );
        }

        self.reply(from, tcp, &ack_datagram).await?;
        self.counters.handshakes.fetch_add(1, Ordering::Relaxed);
        tracing::info!(user = verified.user_id, %ip, %from, "session established");
        Ok(None)
    }
}

async fn flush_ack(s: &mut ServerSession, sock: &UdpSocket) {
    if s.pending == 0 {
        return;
    }
    let ranges = std::mem::take(&mut s.ack);
    s.pending = 0;
    if let Ok((_, datagram)) = s.sess.seal_control_padded(&ranges.encode(), control_size()) {
        deliver(s, sock, &datagram).await;
    }
}

/// Process one in-session control frame. Returns `true` when the client
/// requested a graceful teardown (`Close`); the caller must evict the session.
async fn handle_control(
    s: &mut ServerSession,
    frame_bytes: &[u8],
    now_us: u64,
    sock: &UdpSocket,
) -> bool {
    match frame::peek_type(frame_bytes) {
        Ok(FrameType::Ack) => {
            let Ok(ranges) = AckRanges::decode(frame_bytes) else {
                return false;
            };
            let srtt = s.rtt.smoothed();
            let mut acked_bytes = 0u64;
            let mut newest: Option<(u64, u64)> = None;
            ranges.for_each(|pn| {
                if let Some((t, bytes)) = s.sent.ack(pn) {
                    acked_bytes += bytes;
                    let sample = now_us.saturating_sub(t);
                    if newest.is_none_or(|(prev, _)| pn > prev) {
                        newest = Some((pn, sample));
                    }
                }
            });
            if acked_bytes > 0 {
                s.cc.on_ack(acked_bytes, now_us, srtt);
            }
            if let Some((_, sample)) = newest {
                s.rtt.update(sample);
            }
        }
        Ok(FrameType::Ping) => {
            if let Ok((_, datagram)) = s
                .sess
                .seal_control_padded(&frame::simple(FrameType::Pong), control_size())
            {
                deliver(s, sock, &datagram).await;
            }
        }
        Ok(FrameType::Close) => return true,
        _ => {}
    }
    false
}

/// Send one datagram to a session's current return path.
///
/// A TCP session's replies go into its connection's writer channel; a UDP
/// session's replies go out the shared socket. A closed TCP connection falls
/// back to the UDP path (which will be unreachable for a TCP peer and lets
/// the idle timeout reap the session).
async fn deliver(s: &mut ServerSession, sock: &UdpSocket, datagram: &[u8]) {
    if let Some(tx) = s.tcp.take()
        && tx.send(datagram.to_vec()).await.is_ok()
    {
        s.tcp = Some(tx);
        return;
    }
    let _ = udp::send(sock, datagram, s.peer).await;
}

/// Jittered control-flight size for server-sent frames (same Firefox band as
/// the client: 43–51 B). Kept in sync with `session::control_size`.
fn control_size() -> usize {
    43 + (crate::crypto::random_32()[0] as usize % 9)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KEY_LEN;
    use crate::packet::TUNNEL_MTU;
    use std::sync::Arc;

    async fn node_and_config() -> (ServerNode, crate::TunnelConfig) {
        let tag_key = [0x22u8; KEY_LEN];
        let psk = [0x11u8; KEY_LEN];
        let mut table = TagTable::new();
        table.insert(&tag_key, 42, psk);
        let tags = Arc::new(RwLock::new(table));
        let pool = IpPool::new(Ipv4Addr::new(10, 66, 0, 0), 24);
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let node = ServerNode::new(sock, tags, pool, ServerParams::default());
        let cfg = crate::TunnelConfig {
            server: "127.0.0.1:1".parse().unwrap(),
            donor: crate::DonorSpec::default(),
            psk,
            user_id: 42,
            tag_key,
            mtu: TUNNEL_MTU as u16,
            fingerprint: crate::Fingerprint::Chrome112,
            stealth: crate::StealthLevel::Off,
            handshake_timeout: Duration::from_secs(2),
            shape: crate::shape::ShapeConfig::default(),
            transport: crate::TransportKind::Udp,
        };
        (node, cfg)
    }

    #[tokio::test]
    async fn rejects_a_probe_and_counts_it() {
        let (node, _cfg) = node_and_config().await;
        let bogus = packet::encode_plaintext_control(
            0,
            0,
            &crate::frame::Hello {
                tag: [0xAA; TAG_LEN],
                client_random: [1; 32],
                x25519_pub: [2; 32],
                window: 0,
                mac: [3; crate::auth::MAC_LEN],
            }
            .encode(),
        );
        let from = "127.0.0.1:5000".parse().unwrap();
        assert!(node.handle(&bogus, from, 0, None).await.unwrap().is_none());
        assert_eq!(node.stats().await.rejected_handshakes, 1);
        assert_eq!(node.stats().await.sessions, 0);
    }

    #[tokio::test]
    async fn ignores_unknown_session_tags() {
        let (node, _cfg) = node_and_config().await;
        let mut dg = Header::new(0, 0xDEAD, 1).encode().to_vec();
        dg.extend_from_slice(&[0u8; 32]);
        let from = "127.0.0.1:5000".parse().unwrap();
        assert!(node.handle(&dg, from, 0, None).await.unwrap().is_none());
        assert_eq!(node.stats().await.unknown_tags, 1);
    }

    #[tokio::test]
    async fn handshake_admits_a_session_and_leases_an_address() {
        let (node, cfg) = node_and_config().await;
        let node = Arc::new(node);
        let server_addr = node.local_addr().unwrap();

        // A minimal server loop, exactly as the binary drives it.
        {
            let node = Arc::clone(&node);
            let sock = node.socket();
            tokio::spawn(async move {
                let mut buf = vec![0u8; packet::MAX_DATAGRAM];
                while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                    let _ = node.handle(&buf[..n], from, 0, None).await;
                }
            });
        }

        let client = udp::bind_for(server_addr, 64, true).await.unwrap();
        let (_state, hello) = crate::handshake::start(&cfg, unix_now_secs()).unwrap();
        udp::send(&client, &hello, server_addr).await.unwrap();

        let mut buf = vec![0u8; packet::MAX_DATAGRAM];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), udp::recv(&client, &mut buf))
            .await
            .expect("server must answer the handshake")
            .unwrap();
        assert_eq!(from, server_addr);
        let (_h, frame) = packet::decode_plaintext_control(&buf[..n]).unwrap();
        assert_eq!(frame::peek_type(frame).unwrap(), FrameType::HelloAck);
        let stats = node.stats().await;
        assert_eq!(stats.sessions, 1);
        assert_eq!(stats.handshakes, 1);

        // A second handshake from the same user must replace, not leak.
        let (_s2, hello2) = crate::handshake::start(&cfg, unix_now_secs()).unwrap();
        udp::send(&client, &hello2, server_addr).await.unwrap();
        let (n2, _) = tokio::time::timeout(Duration::from_secs(2), udp::recv(&client, &mut buf))
            .await
            .expect("second handshake must also be answered")
            .unwrap();
        assert!(n2 > 0);
        assert_eq!(node.stats().await.sessions, 1);
    }

    #[tokio::test]
    async fn a_fresh_session_is_not_expired_by_a_long_uptime() {
        // Regression: the session used to be created with `last_rx_us = 0`, so
        // `tick` measured its idle time as the whole server uptime. Any client
        // that connected more than `idle_timeout` after the server started was
        // reaped on the next tick, and every packet it then sent was dropped as
        // an unknown tag — a tunnel that connects and carries nothing.
        let (node, cfg) = node_and_config().await;
        let (_state, hello) = crate::handshake::start(&cfg, unix_now_secs()).unwrap();
        let from: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        // The server has been up for five minutes; the session is born now.
        let now = 300_000_000u64;
        node.handle(&hello, from, now, None).await.unwrap();
        let stats = node.stats().await;
        assert_eq!(stats.sessions, 1);
        assert_eq!(stats.handshakes, 1);

        // A tick one second later must see a one-second-old session, not a
        // five-minute-old one.
        node.tick(now + 1_000_000).await.unwrap();
        assert_eq!(node.stats().await.sessions, 1);

        // Idle expiry still works once the session is genuinely idle.
        node.tick(now + 46_000_000).await.unwrap();
        assert_eq!(node.stats().await.sessions, 0);
    }

    #[tokio::test]
    async fn a_datagram_without_the_control_flag_is_not_a_handshake() {
        let (node, cfg) = node_and_config().await;
        let (_state, hello) = crate::handshake::start(&cfg, unix_now_secs()).unwrap();
        let mut broken = hello;
        broken[0] &= 0xF0; // clear the flag nibble
        let from = "127.0.0.1:5000".parse().unwrap();
        assert!(node.handle(&broken, from, 0, None).await.unwrap().is_none());
        assert_eq!(node.stats().await.rejected_handshakes, 0);
        assert_eq!(node.stats().await.unknown_tags, 1);
    }

    #[tokio::test]
    async fn only_fresh_authenticated_packets_can_change_return_path() {
        let (node, cfg) = node_and_config().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let original = client.local_addr().unwrap();
        let moved: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let attacker: SocketAddr = "127.0.0.1:5002".parse().unwrap();
        let (state, hello) = handshake::start(&cfg, unix_now_secs()).unwrap();
        node.handle(&hello, original, 100, None).await.unwrap();
        let mut buf = vec![0; packet::MAX_DATAGRAM];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let established = handshake::finish(&state, &buf[..n]).unwrap();
        let tag = established.session_tag;
        let session = Session::new(established.keys, tag, TUNNEL_MTU);
        let (_, valid) = session.seal_keepalive().unwrap();
        {
            let mut inner = node.inner.lock().await;
            let s = inner.sessions.get_mut(&tag).unwrap();
            s.next_ping_us = 500;
            s.ping_backoff_us = 8_000_000;
        }
        let mut forged = valid.clone();
        *forged.last_mut().unwrap() ^= 1;
        node.handle(&forged, attacker, 200, None).await.unwrap();
        {
            let inner = node.inner.lock().await;
            let s = &inner.sessions[&tag];
            assert_eq!(s.peer, original);
            assert_eq!(s.last_rx_us, 100);
            assert_eq!(s.next_ping_us, 500);
            assert_eq!(s.ping_backoff_us, 8_000_000);
        }
        // A new authenticated packet permits legitimate NAT rebinding.
        node.handle(&valid, moved, 300, None).await.unwrap();
        {
            let inner = node.inner.lock().await;
            let s = &inner.sessions[&tag];
            assert_eq!(s.peer, moved);
            assert_eq!(s.last_rx_us, 300);
            assert_eq!(s.next_ping_us, 0);
            assert_eq!(s.ping_backoff_us, PING_BACKOFF_BASE_US);
        }
        // Capturing a valid ciphertext must not allow redirecting the session.
        node.handle(&valid, attacker, 400, None).await.unwrap();
        {
            let inner = node.inner.lock().await;
            let s = &inner.sessions[&tag];
            assert_eq!(s.peer, moved);
            assert_eq!(s.last_rx_us, 300);
        }
        // Nor may forged traffic keep a dead session alive indefinitely.
        node.handle(&forged, attacker, 44_000_000, None)
            .await
            .unwrap();
        node.tick(46_000_000).await.unwrap();
        assert_eq!(node.stats().await.sessions, 0);
    }

    #[tokio::test]
    async fn seal_outbound_reports_a_missing_route() {
        let (node, _cfg) = node_and_config().await;
        let pkt = vec![0x45u8; 20];
        assert!(!node.seal_packet(&pkt, 0).await.unwrap());
    }

    #[tokio::test]
    async fn live_snapshot_revokes_one_device_and_preserves_its_sibling() {
        let (node, cfg) = node_and_config().await;
        let key = cfg.tag_key;
        node.replace_tags(
            TagTable::build(&key, &[(42, "11".repeat(32)), (42, "33".repeat(32))]).unwrap(),
        )
        .await
        .unwrap();
        let mut sessions = Vec::new();
        let mut hellos = Vec::new();
        let mut addresses = Vec::new();
        let mut clients = Vec::new();
        for psk in [[0x11; 32], [0x33; 32]] {
            let mut device = cfg.clone();
            device.psk = psk;
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (state, hello) = handshake::start(&device, unix_now_secs()).unwrap();
            node.handle(&hello, client.local_addr().unwrap(), 100, None)
                .await
                .unwrap();
            let mut bytes = [0; packet::MAX_DATAGRAM];
            let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            let established = handshake::finish(&state, &bytes[..n]).unwrap();
            addresses.push(established.assigned_ip);
            sessions.push(Session::new(
                established.keys,
                established.session_tag,
                TUNNEL_MTU,
            ));
            hellos.push(hello);
            clients.push(client);
        }
        assert_ne!(addresses[0], addresses[1]);
        assert_eq!(node.stats().await.sessions, 2);
        let before = node.stats().await.handshakes;
        assert_eq!(
            node.replace_tags(TagTable::build(&key, &[(42, "33".repeat(32))]).unwrap())
                .await
                .unwrap(),
            1
        );
        assert_eq!(node.stats().await.sessions, 1);
        for (index, session) in sessions.iter().enumerate() {
            let mut pkt = vec![0x45; 20];
            pkt[12..16].copy_from_slice(&addresses[index].octets());
            let (_, encrypted) = session.seal_ip(&pkt).unwrap();
            let received = node
                .handle(&encrypted, clients[index].local_addr().unwrap(), 200, None)
                .await
                .unwrap();
            assert_eq!(received.is_some(), index == 1);
        }
        // A previously cached HELLO must not resurrect the revoked device.
        node.handle(&hellos[0], clients[0].local_addr().unwrap(), 300, None)
            .await
            .unwrap();
        assert_eq!(node.stats().await.handshakes, before);
        assert_eq!(node.stats().await.rejected_handshakes, 1);
        assert_eq!(node.tags.read().unwrap().leased_ips(), vec![addresses[1]]);
        // A delayed surviving HELLO remains idempotent across a hot snapshot.
        node.handle(&hellos[1], clients[1].local_addr().unwrap(), 350, None)
            .await
            .unwrap();
        assert_eq!(node.stats().await.handshakes, before);
        // Re-applying the same authorization keeps the surviving session.
        assert_eq!(
            node.replace_tags(TagTable::build(&key, &[(42, "33".repeat(32))]).unwrap())
                .await
                .unwrap(),
            0
        );
        assert_eq!(node.stats().await.sessions, 1);
    }
}

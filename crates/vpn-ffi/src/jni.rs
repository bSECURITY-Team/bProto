//! JNI entry points for the Android client (`--features jni`).
//!
//! Kotlin sees a singleton, `dev.bproto.Bproto`, declared as a Kotlin `object`
//! with `external` members. An `object`'s members compile to *instance* methods
//! (the receiver is the singleton), so the symbols are
//! `Java_dev_bproto_Bproto_<name>` with a `jobject` in the second slot. Do not
//! add `@JvmStatic` on the Kotlin side: that emits a second, static method with
//! the same descriptor and the runtime resolves the wrong one.
//!
//! The Android runtime owns the VPN file descriptor (from `VpnService`), while
//! this crate owns the socket that talks to the server. The app must call
//! [`Java_dev_bproto_Bproto_socketFd`] and pass the result to
//! `VpnService.protect()` before handing us the tunnel descriptor, otherwise the
//! encapsulated traffic is routed back into the tunnel.
//!
//! The datapath is IPv4 only. IPv6 is captured by `::/0` on the Android side so
//! it cannot leak in the clear; instead of silently black-holing it (which makes
//! every v6 `connect()` wait for a full TCP timeout), the reader answers with an
//! ICMPv6 "no route to destination", so the kernel fails fast and applications
//! fall back to IPv4. Nothing IPv6 ever leaves the tunnel or the device.
//!
//! Threading: `connect` blocks while the handshake runs and `pump` blocks for the
//! whole life of the tunnel. Both must be called from a worker thread that the
//! app owns; `stop`, `reset`, `pumpActive` and `stats` are safe from any thread.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;

use jni::{JNIEnv, JavaVM};
use jni::objects::{GlobalRef, JObject, JString, JValue};
use jni::sys::{jint, jlong, jstring};
use tokio::sync::{Notify, mpsc};

use crate::BprotoTunnel;

#[cfg(test)]
mod tests;

/// Wake-up channel pair width: enough to smooth a scheduling hiccup without
/// letting a stalled peer grow the queue without bound.
const CHANNEL_DEPTH: usize = 128;
/// How long a tun-side thread waits for the descriptor before rechecking stop.
const POLL_MS: i32 = 200;
/// Largest IP packet we will read from the tun descriptor.
const TUN_BUF: usize = 65_535;
/// How much of the offending packet to quote in an ICMPv6 error. The kernel
/// only needs the IPv6 header plus the first bytes of the L4 header to match a
/// socket; keeping this small stays far below any tun MTU.
const ICMPV6_QUOTE: usize = 256;
/// Source address of our synthetic ICMPv6 errors: `fd00:6270:726f:746f::1`,
/// the gateway of the ULA the Android builder assigns to the tun interface.
const V6_GATEWAY: [u8; 16] = [
    0xfd, 0x00, 0x62, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0, 0, 0, 0, 0, 0, 0, 0x01,
];

/// The `Notify` currently armed for the running tunnel. Replaced on every `run`
/// so a stale signal from a previous session cannot stop a fresh one.
fn stop_slot() -> &'static Mutex<Arc<Notify>> {
    static SLOT: OnceLock<Mutex<Arc<Notify>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(Arc::new(Notify::new())))
}

/// A stop that arrived while `pump` had not started yet. `Notify` alone loses
/// that race: `stop()` signals the *old* slot, and `rearm_stop()` then replaces
/// it, so the new pump would run forever. The flag survives `rearm_stop()`.
/// `Java_dev_bproto_Bproto_reset` clears it at the start of every connect.
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Arm a fresh signal and return it. The pending-stop flag is deliberately
/// *not* cleared here — the caller checks it before arming.
fn rearm_stop() -> Arc<Notify> {
    let mut slot = stop_slot().lock().expect("stop slot poisoned");
    *slot = Arc::new(Notify::new());
    Arc::clone(&slot)
}

fn current_stop() -> Arc<Notify> {
    Arc::clone(&stop_slot().lock().expect("stop slot poisoned"))
}

/// Only one tunnel can be pumped per process; the Kotlin service enforces this
/// too, but the native side must not be corrupted by a double call. Also the
/// "datapath is actually running" signal the UI waits for before saying
/// "connected".
static PUMPING: AtomicBool = AtomicBool::new(false);

struct PumpGuard;

impl Drop for PumpGuard {
    fn drop(&mut self) {
        PUMPING.store(false, Ordering::SeqCst);
    }
}

/// JVM-side `VpnService.protect(fd)` callback. Held as a global reference so
/// native threads that open sockets (tokio's handshake runtime is *not* the
/// thread that called `connect`) can still call into Kotlin.
struct JavaProtector {
    vm: JavaVM,
    callback: GlobalRef,
}

static JAVA_PROTECTOR: Mutex<Option<Arc<JavaProtector>>> = Mutex::new(None);

impl JavaProtector {
    fn protect(&self, fd: RawFd) -> bool {
        // A socket can be opened from any tokio worker thread. Attach for the
        // duration of the call; the guard detaches us again on drop.
        let mut env = match self.vm.attach_current_thread() {
            Ok(env) => env,
            Err(e) => {
                tracing::warn!(error = %e, "cannot attach to JVM to protect a socket");
                return false;
            }
        };
        let value = env.call_method(
            self.callback.as_obj(),
            "protectFd",
            "(I)Z",
            &[JValue::Int(fd)],
        );
        if env.exception_check().unwrap_or(true) {
            let _ = env.exception_clear();
            return false;
        }
        value.ok().and_then(|v| v.z().ok()).unwrap_or(false)
    }
}

fn clear_java_protector() {
    vpn_core::socket_protect::clear_socket_protector();
    let mut slot = JAVA_PROTECTOR
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *slot = None;
}

fn install_java_protector(
    env: &mut JNIEnv<'_>,
    protector: &JObject<'_>,
) -> Result<(), String> {
    let vm = env
        .get_java_vm()
        .map_err(|e| format!("cannot get JavaVM: {e}"))?;
    let callback = env
        .new_global_ref(protector)
        .map_err(|e| format!("cannot pin the socket protector: {e}"))?;
    let holder = Arc::new(JavaProtector { vm, callback });
    let for_hook = Arc::clone(&holder);
    let hook: Arc<dyn Fn(RawFd) -> bool + Send + Sync + 'static> =
        Arc::new(move |fd| for_hook.protect(fd));
    vpn_core::socket_protect::set_socket_protector(Some(hook));
    let mut slot = JAVA_PROTECTOR
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *slot = Some(holder);
    Ok(())
}

/// Register (or clear, with `null`) the Kotlin object whose `protectFd(I)Z`
/// method calls `VpnService.protect()`. Must be called before `connect()`, so
/// both UDP and TCP fallback sockets are marked before their first packet.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_setSocketProtector<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    protector: JObject<'local>,
) {
    if protector.as_raw().is_null() {
        clear_java_protector();
        return;
    }
    if let Err(e) = install_java_protector(&mut env, &protector) {
        clear_java_protector();
        crate::set_error(&e);
    }
}

fn new_string(env: &mut JNIEnv<'_>, value: &str) -> jstring {
    match env.new_string(value) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn read_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Result<String, String> {
    env.get_string(value)
        .map(Into::into)
        .map_err(|e| format!("config string is not readable: {e}"))
}

/// Library version. Mirrors `bproto_version`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_version<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
) -> jstring {
    new_string(&mut env, env!("CARGO_PKG_VERSION"))
}

/// Message from the most recent failing call on this thread (empty if none).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_lastError<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
) -> jstring {
    let msg = crate::last_error_string();
    new_string(&mut env, &msg)
}

/// Connect: run the handshake and return an opaque handle, or 0 on failure.
///
/// `config` is either the JSON `TunnelConfig` or a `bproto://import/...` key.
/// Blocks the calling thread until the handshake completes or times out.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_connect<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    config: JString<'local>,
) -> jlong {
    let text = match read_string(&mut env, &config) {
        Ok(s) => s,
        Err(e) => {
            crate::set_error(&e);
            return 0;
        }
    };
    let Ok(cstr) = std::ffi::CString::new(text) else {
        crate::set_error("config contains a NUL byte");
        return 0;
    };
    // SAFETY: `cstr` is a valid NUL-terminated string alive for the call.
    let handle = unsafe { crate::bproto_connect(cstr.as_ptr()) };
    handle as jlong
}

/// Address the server leased to this tunnel, e.g. `"10.66.0.2"`. Empty on error.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_assignedIp<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
) -> jstring {
    let mut octets = [0u8; 4];
    // SAFETY: the caller passes a handle from `connect`; `octets` is 4 bytes.
    let rc = unsafe { crate::bproto_assigned_ip(handle as *mut BprotoTunnel, octets.as_mut_ptr()) };
    if rc != 0 {
        return new_string(&mut env, "");
    }
    let ip = std::net::Ipv4Addr::from(octets);
    new_string(&mut env, &ip.to_string())
}

/// UDP socket descriptor of the server link — pass it to `VpnService.protect`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_socketFd<'local>(
    _env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
) -> jint {
    // SAFETY: the caller passes a handle from `connect`.
    unsafe { crate::bproto_socket_fd(handle as *mut BprotoTunnel) }
}

/// Pump packets between the tunnel and an Android tun descriptor until `stop`.
///
/// Returns null on a clean stop, or an error message the UI should show.
/// Blocks the calling thread for the whole tunnel lifetime.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_pump<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
    fd: jint,
) -> jstring {
    match run_pump(handle as *mut BprotoTunnel, fd as RawFd) {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => new_string(&mut env, &e),
    }
}

/// Ask a running `pump` call to return. Safe to call from any thread.
///
/// The flag also covers a stop that arrives *before* `pump` starts: a plain
/// `Notify` would be armed on a fresh slot by `rearm_stop()` and the signal
/// would be lost, leaving a cancelled tunnel running forever.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_stop(_env: JNIEnv<'_>, _this: JObject<'_>) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
    current_stop().notify_one();
}

/// Clear a stale stop request. The service calls this before each new connect
/// (and before each fallback candidate) so a previous teardown cannot cancel a
/// fresh session, while a real disconnect raised during setup still sticks.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_reset(_env: JNIEnv<'_>, _this: JObject<'_>) {
    STOP_REQUESTED.store(false, Ordering::SeqCst);
}

/// 1 while the native packet pump is running, 0 otherwise. The UI must not say
/// "connected" on the handshake alone; it waits for this to become 1.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_pumpActive(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
) -> jint {
    i32::from(PUMPING.load(Ordering::SeqCst))
}

/// Counters for the status line / logcat, or an empty string on a bad handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_stats<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
) -> jstring {
    let mut snap = crate::BprotoStats::default();
    // SAFETY: the caller passes a live handle from `connect`; `snap` is a
    // writable `BprotoStats`.
    let rc = unsafe { crate::bproto_stats(handle as *mut BprotoTunnel, &mut snap) };
    if rc != 0 {
        return new_string(&mut env, "");
    }
    new_string(
        &mut env,
        &format!(
            "rx={} tx={} dropped={} rtt_ms={:.1}",
            snap.rx_bytes,
            snap.tx_bytes,
            snap.dropped,
            snap.rtt_us as f64 / 1000.0
        ),
    )
}

/// Release a handle from `connect`. Does not stop a running `pump` call.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_close(
    _env: JNIEnv<'_>,
    _this: JObject<'_>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: the pointer came from `connect` and is freed exactly once.
    unsafe { crate::bproto_free(handle as *mut BprotoTunnel) };
}

fn run_pump(handle: *mut BprotoTunnel, fd: RawFd) -> Result<(), String> {
    if handle.is_null() {
        return Err("tunnel handle is null".to_owned());
    }
    if fd < 0 {
        return Err("tun descriptor is invalid".to_owned());
    }
    // A disconnect raised while the handshake/establish was still in progress
    // must not be lost by `rearm_stop()` below.
    if STOP_REQUESTED.load(Ordering::SeqCst) {
        return Ok(());
    }
    if PUMPING.swap(true, Ordering::SeqCst) {
        return Err("a tunnel is already running".to_owned());
    }
    let _guard = PumpGuard;

    // SAFETY: the handle is live for the whole call; the Kotlin service keeps
    // the handle and the descriptor alive until `run` returns.
    let owner = unsafe { &*handle };
    let notify = rearm_stop();

    set_nonblocking(fd).map_err(|e| format!("tun descriptor: {e}"))?;

    // tun -> tunnel (reader thread) and tunnel -> tun (writer thread), with the
    // async pump in the middle. Using channels here keeps every read/write off
    // the runtime threads: the tun descriptor is a blocking object we do not own.
    let (fd_tx, mut fd_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
    let (to_fd_tx, mut to_fd_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
    // The reader also owns a sender on the *downlink* channel: captured IPv6
    // packets are answered with an ICMPv6 error instead of being black-holed.
    let inject_tx = to_fd_tx.clone();

    let reader = spawn_thread("bproto-tun-read", move || tun_reader(fd, fd_tx, inject_tx))?;
    let writer = spawn_thread("bproto-tun-write", move || tun_writer(fd, &mut to_fd_rx))?;

    let outcome = owner.rt.block_on(async move {
        loop {
            if STOP_REQUESTED.load(Ordering::SeqCst) {
                return Ok(());
            }
            tokio::select! {
                // `biased` keeps shutdown and inbound traffic ahead of the
                // reader channel, so a busy tunnel still stops promptly.
                biased;
                () = notify.notified() => return Ok(()),
                inbound = owner.tunnel.recv_ip_packet() => match inbound {
                    Ok(packet) => {
                        if to_fd_tx.send(packet).await.is_err() {
                            return Ok(());
                        }
                    }
                    Err(e) => return Err(format!("tunnel receive: {e}")),
                },
                outbound = fd_rx.recv() => match outbound {
                    Some(packet) => {
                        // One oversized or transiently unsendable packet must
                        // not tear down the whole tunnel. The Linux CLI simply
                        // logs and continues (`vpn-cli/src/main.rs`); the
                        // Android pump used to `return Err` here, which is why
                        // the UI said "connected" and every request then timed
                        // out. Check the negotiated MTU first so the common
                        // `PayloadTooLarge` case never even reaches the AEAD.
                        if packet.len() > owner.tunnel.mtu() {
                            tracing::debug!(
                                len = packet.len(),
                                mtu = owner.tunnel.mtu(),
                                "outbound packet larger than tunnel MTU; dropped"
                            );
                        } else if let Err(e) = owner.tunnel.send_ip_packet(&packet).await {
                            tracing::debug!(error = %e, "outbound packet dropped");
                        }
                    }
                    None => return Ok(()),
                },
            }
        }
    });

    // The `async move` block owns both channel halves, so they are dropped the
    // moment it returns: the reader sees its uplink send fail and exits, which
    // drops its downlink clone; the writer then sees the channel close. That is
    // what ends the tun threads.
    current_stop().notify_one();
    join_thread(reader);
    join_thread(writer);

    // Best-effort Close frame; ignore failures on an already dead session.
    owner.rt.block_on(owner.tunnel.close());
    outcome
}

fn spawn_thread(
    name: &str,
    body: impl FnOnce() + Send + 'static,
) -> Result<JoinHandle<()>, String> {
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(body)
        .map_err(|e| format!("cannot start {name}: {e}"))
}

fn join_thread(handle: JoinHandle<()>) {
    if handle.join().is_err() {
        tracing::warn!("a tun worker thread panicked");
    }
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: plain fcntl on a descriptor the caller owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Wait up to [`POLL_MS`] for `events`. `Ok(true)` means ready.
fn wait_fd(fd: RawFd, events: libc::c_short) -> std::io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    // SAFETY: one valid pollfd, one element.
    let rc = unsafe { libc::poll(&mut pfd, 1, POLL_MS) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(err);
    }
    if rc == 0 {
        return Ok(false);
    }
    // `poll()` returns > 0 for POLLERR/POLLHUP/POLLNVAL too. Treating those as
    // "ready" and writing anyway used to kill the downlink silently.
    if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(std::io::Error::other(format!(
            "tun descriptor error, revents=0x{:x}",
            pfd.revents
        )));
    }
    Ok(pfd.revents & events != 0)
}

fn tun_reader(
    fd: RawFd,
    tx: mpsc::Sender<Vec<u8>>,
    inject_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut buf = vec![0u8; TUN_BUF];
    loop {
        // The pump drops the receiving half when it returns. Nothing else
        // reports that to a thread parked in `poll`, so ask the channel
        // directly — otherwise this thread outlives the tunnel forever.
        if tx.is_closed() {
            return;
        }
        match wait_fd(fd, libc::POLLIN) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "tun read poll failed");
                return;
            }
        }
        // SAFETY: `buf` is writable for its full length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n == 0 {
            return; // descriptor closed by the app
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => continue,
                _ => {
                    tracing::warn!(error = %err, "tun read failed");
                    return;
                }
            }
        }
        let packet = buf[..n as usize].to_vec();
        // The tunnel carries IPv4 only. IPv6 is captured by `::/0` so it
        // cannot leak in the clear; forwarding it would blow the MTU
        // (`PayloadTooLarge`). Silently dropping it, however, black-holes
        // every v6 connect(): no ICMPv6, no RST, the app waits for the full
        // TCP SYN timeout and never reaches its IPv4 fallback on IPv6-first /
        // DNS64 networks. Answer with an ICMPv6 "no route to destination"
        // instead — the kernel fails the v6 socket immediately and Happy
        // Eyeballs switches to IPv4. Best effort: a full channel only means
        // the reply is dropped, never that the reader blocks.
        let version = packet.first().map(|b| b >> 4).unwrap_or(0);
        if version != 4 {
            if let Some(reply) = icmpv6_no_route(&packet) {
                match inject_tx.try_send(reply) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                }
            }
            continue;
        }
        if tx.blocking_send(packet).is_err() {
            return; // tunnel shut down
        }
    }
}

/// Build an ICMPv6 Destination Unreachable (type 1, code 0 = "no route to
/// destination") quoting the offending packet, so the Android kernel can fail
/// the corresponding v6 socket instead of letting it time out.
///
/// Returns `None` for packets we must not answer (malformed, multicast,
/// unspecified source, neighbour discovery, ICMPv6 errors) — those are dropped
/// silently, which is correct for ND/multicast and avoids ICMP error loops.
fn icmpv6_no_route(original: &[u8]) -> Option<Vec<u8>> {
    if original.len() < 40 || original[0] >> 4 != 6 {
        return None;
    }
    let src = &original[8..24];
    let dst = &original[24..40];
    if src[0] == 0xff || dst[0] == 0xff || src.iter().all(|&b| b == 0) {
        return None;
    }
    // Walk the (short) extension-header chain so TCP/UDP/ICMPv6 behind a
    // hop-by-hop or destination-options header is still failed fast. Encrypted
    // and fragmented payloads are left alone: we cannot identify a socket from
    // them, and answering a fragment would be wrong.
    let mut next = original[6];
    let mut offset = 40usize;
    loop {
        match next {
            // TCP and UDP are the connections we want to fail fast.
            6 | 17 => break,
            // Informational ICMPv6 (echo request and friends), but never an
            // ICMPv6 error or neighbour discovery, per RFC 4443 §2.4.
            58 if offset + 1 <= original.len() && original[offset] >= 128 => break,
            // Hop-by-hop, routing and destination options: skip Hdr Ext Len
            // units of 8 bytes, starting after the 2-byte header.
            0 | 43 | 60 if offset + 2 <= original.len() => {
                next = original[offset];
                offset += 8 * (original[offset + 1] as usize + 1);
                if offset > original.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }

    let quote = original.len().min(ICMPV6_QUOTE);
    let icmp_len = 8 + quote;
    let mut pkt = Vec::with_capacity(40 + icmp_len);
    // IPv6 header: v6, no flow label, payload = ICMPv6, next header = 58,
    // hop limit 64, from our ULA gateway to the packet's source.
    pkt.extend_from_slice(&[0x60, 0, 0, 0]);
    pkt.extend_from_slice(&(icmp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[58, 64]);
    pkt.extend_from_slice(&V6_GATEWAY);
    pkt.extend_from_slice(src);
    // ICMPv6 header: type 1, code 0, checksum zero for now, unused = 0.
    pkt.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    pkt.extend_from_slice(&original[..quote]);

    // ICMPv6 checksum covers the IPv6 pseudo-header as well (RFC 4443 §2.3).
    let mut pseudo = Vec::with_capacity(40 + icmp_len);
    pseudo.extend_from_slice(&V6_GATEWAY);
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(&(icmp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(&pkt[40..]);
    let sum = internet_checksum(&pseudo);
    pkt[42..44].copy_from_slice(&sum.to_be_bytes());
    Some(pkt)
}

/// RFC 1071 one's-complement checksum over a byte slice (odd lengths are
/// padded with a zero byte on the right).
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tun_writer(fd: RawFd, rx: &mut mpsc::Receiver<Vec<u8>>) {
    while let Some(packet) = rx.blocking_recv() {
        write_all(fd, &packet);
    }
}

/// Write a packet, retrying a bounded number of times on a busy descriptor.
/// A dropped packet is logged: silent drops here look exactly like "the tunnel
/// connects but nothing comes back".
fn write_all(fd: RawFd, packet: &[u8]) {
    const MAX_BUSY: u32 = 10;
    let mut offset = 0;
    let mut busy = 0u32;
    while offset < packet.len() {
        match wait_fd(fd, libc::POLLOUT) {
            Ok(true) => {}
            Ok(false) => {
                busy += 1;
                if busy > MAX_BUSY {
                    tracing::debug!(len = packet.len(), "tun write timed out; packet dropped");
                    return;
                }
                continue;
            }
            Err(e) => {
                tracing::debug!(error = %e, "tun write poll failed; packet dropped");
                return;
            }
        }
        // SAFETY: `packet[offset..]` is readable for its full length.
        let n = unsafe { libc::write(fd, packet[offset..].as_ptr().cast(), packet.len() - offset) };
        if n > 0 {
            offset += n as usize;
            busy = 0;
            continue;
        }
        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => busy += 1,
            _ => {
                tracing::debug!(error = %err, "tun write failed; packet dropped");
                return;
            }
        }
        if busy > MAX_BUSY {
            tracing::debug!(len = packet.len(), "tun write busy; packet dropped");
            return;
        }
    }
}

mod quic_carrier;

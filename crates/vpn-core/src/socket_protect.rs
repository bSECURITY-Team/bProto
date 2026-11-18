//! Platform hook for protecting the tunnel's own sockets from the VPN.
//!
//! `vpn-core` stays platform-agnostic: it only knows "a socket has just been
//! created, give the embedder a chance to exempt it before anything is sent".
//! Android installs a callback that calls `VpnService.protect(fd)`; the CLI and
//! the server never install one and therefore pay nothing. This is deliberately
//! called **before** `connect(2)`/`sendto(2)`: protecting after the handshake
//! is too late for TCP fallback sockets, whose SYN would already be inside the
//! tunnel.

#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(unix)]
use std::sync::{Arc, RwLock};

#[cfg(not(unix))]
use crate::Result;
#[cfg(unix)]
use crate::{Error, Result};

#[cfg(unix)]
type Protector = dyn Fn(RawFd) -> bool + Send + Sync + 'static;

#[cfg(unix)]
static PROTECTOR: RwLock<Option<Arc<Protector>>> = RwLock::new(None);

/// Install (or clear) the socket-protection hook. Replacing it is allowed: the
/// Android service does that on every connect and on every default-network
/// change so a stale `VpnService` instance is never called.
#[cfg(unix)]
pub fn set_socket_protector(protector: Option<Arc<Protector>>) {
    let mut slot = PROTECTOR.write().unwrap_or_else(|e| e.into_inner());
    *slot = protector;
}

/// Clear the hook. Convenience for embedders that do not want to spell out the
/// type of `None`.
#[cfg(unix)]
pub fn clear_socket_protector() {
    set_socket_protector(None);
}

/// Exempt `fd` from the VPN. A missing hook is a no-op (desktop / CLI);
/// returning `false` from an installed hook is fatal for the connection rather
/// than silently creating a routing loop.
#[cfg(unix)]
pub fn protect_socket(fd: RawFd) -> Result<()> {
    let hook = PROTECTOR
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .cloned();
    match hook {
        Some(hook) if hook(fd) => Ok(()),
        Some(_) => Err(Error::Transport(format!(
            "VPN socket protection failed for fd {fd}"
        ))),
        None => Ok(()),
    }
}

/// Non-Unix parity: the hook is always absent, so protecting is a no-op.
#[cfg(not(unix))]
pub fn protect_socket(_fd: i32) -> Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, Ordering};

    #[test]
    fn hook_is_invoked_and_can_be_cleared() {
        // A sentinel that no real socket can have: the hook stays harmless for
        // parallel tests that call `protect_socket()` with a live fd.
        const FAIL_FD: RawFd = -123_456;
        clear_socket_protector();
        assert!(protect_socket(1).is_ok(), "no hook must be a no-op");

        let seen = Arc::new(AtomicI32::new(-1));
        let seen_hook = Arc::clone(&seen);
        set_socket_protector(Some(Arc::new(move |fd| {
            seen_hook.store(fd, Ordering::SeqCst);
            fd != FAIL_FD
        })));
        assert!(protect_socket(77).is_ok());
        assert_eq!(seen.load(Ordering::SeqCst), 77);

        assert!(matches!(protect_socket(FAIL_FD), Err(Error::Transport(_))));

        clear_socket_protector();
        assert!(protect_socket(79).is_ok());
    }
}

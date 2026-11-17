//! The routing tag table: `tag -> (user, psk)`.
//!
//! The panel is the source of truth; servers hold this table in memory and
//! refresh it through a validated snapshot. Runtime revocation must also evict
//! sessions through `ServerNode::replace_tags`; table removal alone is not enough.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::auth::{TAG_LEN, compute_tag};
use crate::config::from_hex;
use crate::crypto::KEY_LEN;
use sha2::{Digest, Sha256};

/// Bound unauthenticated MAC verification work for one routing tag.
pub const MAX_KEYS_PER_USER: usize = 16;

/// Internal credential identity; never transmitted or logged.
#[must_use]
pub fn credential_id(psk: &[u8; KEY_LEN]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"bproto internal credential v1");
    hash.update(psk);
    hash.finalize().into()
}

/// One user's authentication material.
#[derive(Debug, Clone)]
struct Entry {
    psks: Vec<[u8; KEY_LEN]>,
    user_id: u64,
    /// Address currently leased to this user, if any.
    ip: Option<Ipv4Addr>,
}

/// In-memory tag table.
#[derive(Debug, Default)]
pub struct TagTable {
    by_tag: HashMap<[u8; TAG_LEN], Entry>,
    by_ip: HashMap<Ipv4Addr, [u8; TAG_LEN]>,
}

impl TagTable {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a user list and the shared routing tag key.
    pub fn build(tag_key: &[u8; KEY_LEN], users: &[(u64, String)]) -> Result<Self, String> {
        let mut t = Self::new();
        for (id, psk_hex) in users {
            let psk = parse_psk(psk_hex)?;
            let tag = compute_tag(tag_key, *id);
            let entry = t.by_tag.entry(tag).or_insert_with(|| Entry {
                psks: Vec::new(),
                user_id: *id,
                ip: None,
            });
            if entry.user_id != *id || entry.psks.contains(&psk) {
                return Err("duplicate credential or routing tag collision".into());
            }
            if entry.psks.len() >= MAX_KEYS_PER_USER {
                return Err("too many credentials for one user".into());
            }
            entry.psks.push(psk);
        }
        Ok(t)
    }

    /// Insert or replace one user.
    pub fn insert(&mut self, tag_key: &[u8; KEY_LEN], user_id: u64, psk: [u8; KEY_LEN]) {
        self.remove(tag_key, user_id);
        let tag = compute_tag(tag_key, user_id);
        self.by_tag.insert(
            tag,
            Entry {
                psks: vec![psk],
                user_id,
                ip: None,
            },
        );
    }

    /// Remove a user (immediate revocation).
    pub fn remove(&mut self, tag_key: &[u8; KEY_LEN], user_id: u64) {
        let tag = compute_tag(tag_key, user_id);
        self.by_tag.remove(&tag);
        self.by_ip.retain(|_, owner| owner != &tag);
    }

    /// Look up the PSK and user id for a routing tag.
    #[must_use]
    pub fn lookup(&self, tag: &[u8; TAG_LEN]) -> Option<([u8; KEY_LEN], u64)> {
        self.candidates(tag).next()
    }

    /// Bounded PSK candidates for legacy uid/tag credentials.
    pub fn candidates(
        &self,
        tag: &[u8; TAG_LEN],
    ) -> impl Iterator<Item = ([u8; KEY_LEN], u64)> + '_ {
        self.by_tag
            .get(tag)
            .into_iter()
            .flat_map(|e| e.psks.iter().map(|psk| (*psk, e.user_id)))
    }

    /// Whether a credential remains authorized in this snapshot.
    #[must_use]
    pub fn contains_credential(&self, tag: &[u8; TAG_LEN], id: &[u8; 32]) -> bool {
        self.candidates(tag)
            .any(|(psk, _)| &credential_id(&psk) == id)
    }

    /// Bind an independently leased device address.
    pub fn bind_address(&mut self, tag: &[u8; TAG_LEN], ip: Ipv4Addr) {
        if self.by_tag.contains_key(tag) {
            self.by_ip.insert(ip, *tag);
        }
    }

    /// Release exactly one device lease, without affecting sibling credentials.
    pub fn release_address(&mut self, ip: Ipv4Addr) {
        self.by_ip.remove(&ip);
    }

    /// Bind a tunnel address to a tag. Replaces any previous lease for that tag.
    pub fn bind_ip(&mut self, tag: &[u8; TAG_LEN], ip: Ipv4Addr) {
        if let Some(e) = self.by_tag.get_mut(tag) {
            if let Some(old) = e.ip.replace(ip) {
                self.by_ip.remove(&old);
            }
            self.by_ip.insert(ip, *tag);
        }
    }

    /// Release the address leased to a tag.
    pub fn release_ip(&mut self, tag: &[u8; TAG_LEN]) {
        if let Some(e) = self.by_tag.get_mut(tag)
            && let Some(ip) = e.ip.take()
        {
            self.by_ip.remove(&ip);
        }
    }

    /// Reverse map: which tag owns this tunnel address.
    #[must_use]
    pub fn tag_for_ip(&self, ip: Ipv4Addr) -> Option<[u8; TAG_LEN]> {
        self.by_ip.get(&ip).copied()
    }

    /// All currently leased addresses.
    #[must_use]
    pub fn leased_ips(&self) -> Vec<Ipv4Addr> {
        self.by_ip.keys().copied().collect()
    }

    /// Number of known users.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_tag.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_tag.is_empty()
    }
}

/// Parse a 32-byte hex PSK.
pub fn parse_psk(hex: &str) -> Result<[u8; KEY_LEN], String> {
    from_hex(hex)?
        .try_into()
        .map_err(|_| "expected 32-byte hex".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_lookup_and_revoke() {
        let key = [0x01u8; KEY_LEN];
        let mut t = TagTable::new();
        t.insert(&key, 1, [0x11; KEY_LEN]);
        let tag = compute_tag(&key, 1);
        assert_eq!(t.lookup(&tag), Some(([0x11; KEY_LEN], 1)));

        t.remove(&key, 1);
        assert_eq!(t.lookup(&tag), None);
        assert!(t.is_empty());
    }

    #[test]
    fn ip_lease_is_bidirectional_and_releasable() {
        let key = [0x02u8; KEY_LEN];
        let mut t = TagTable::new();
        t.insert(&key, 5, [0x22; KEY_LEN]);
        let tag = compute_tag(&key, 5);

        t.bind_ip(&tag, Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(t.tag_for_ip(Ipv4Addr::new(10, 66, 0, 2)), Some(tag));
        assert_eq!(t.leased_ips(), vec![Ipv4Addr::new(10, 66, 0, 2)]);

        // rebinding releases the old address
        t.bind_ip(&tag, Ipv4Addr::new(10, 66, 0, 3));
        assert_eq!(t.tag_for_ip(Ipv4Addr::new(10, 66, 0, 2)), None);
        assert_eq!(t.tag_for_ip(Ipv4Addr::new(10, 66, 0, 3)), Some(tag));

        // revocation releases both
        t.remove(&key, 5);
        assert_eq!(t.tag_for_ip(Ipv4Addr::new(10, 66, 0, 3)), None);
    }

    #[test]
    fn build_from_user_list() {
        let key = [0x03u8; KEY_LEN];
        let users = vec![(1u64, "11".repeat(32)), (2u64, "22".repeat(32))];
        let t = TagTable::build(&key, &users).unwrap();
        assert_eq!(t.len(), 2);
        assert!(TagTable::build(&key, &[(3, "zz".into())]).is_err());
    }

    #[test]
    fn snapshots_keep_sibling_credentials_and_reject_duplicates_or_excess() {
        let key = [3; KEY_LEN];
        let users = vec![(1, "11".repeat(32)), (1, "22".repeat(32))];
        let t = TagTable::build(&key, &users).unwrap();
        assert_eq!(t.candidates(&compute_tag(&key, 1)).count(), 2);
        assert!(TagTable::build(&key, &[(1, "11".repeat(32)), (1, "11".repeat(32))]).is_err());
        let excessive = (0..=MAX_KEYS_PER_USER)
            .map(|n| (1, format!("{n:064x}")))
            .collect::<Vec<_>>();
        assert!(TagTable::build(&key, &excessive).is_err());
    }
}

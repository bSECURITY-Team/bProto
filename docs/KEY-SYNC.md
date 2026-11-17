# Automatic credential synchronization (Linux, opt-in)

[Русская версия](KEY-SYNC.ru.md)

The panel now reconciles one configured inbound through the existing mTLS agent.
It is disabled until provisioned. A key displayed in the panel is not accepted
by the server until its desired revision is confirmed applied. Clients shows
delivery status and the selected inbound; other inbounds are not synchronized.

## Contract and compatibility

The VPN handshake, crypto primitives, server/client TOML and import URI formats
are unchanged. One uid/tag may hold up to 16 active PSKs; each credential gets
an independent session/lease. Reconnect replaces the same credential's session.
A hot snapshot preserves unchanged sessions and evicts removed credentials,
leases, routes and cached HELLOs under the protocol node's update lock.

Agent v1 JSON/TLS operations remain supported on ordinary agent instances.
A users-enabled instance accepts only the separate version-2 users operation;
generic apply/rollback cannot bypass revocation protection. Unknown versions
and fields fail. A snapshot includes revision, inbound_id, users, managed uid ownership, revoked
credential identities and a full HMAC proof derived with the existing tag key.
The proof binds the exact canonical document and revision, detecting a mismatched
BPROTO_TAG_KEY before file mutation. Durable monotonic revisions reject replay;
there is no separate challenge round-trip. No key/proof/body is logged.

SQLite triggers atomically record desired revisions with credential mutations.
The worker sends only active local credentials eligible by inbound/user status,
expiry and quota. It also detects time-based expiry. Remote subscription keys
are not provisioned. Revoke/delete create durable tombstones; disable/expiry
can be reversed. A lost HTTP response retries the same revision without reload.

SQLite and the remote server are not a global ACID transaction. Pending means
the server has not confirmed enforcement. Never treat pending as a completed revoke.

## Provisioning

Use Python 3.11+, a Linux server and a private management network/CA.
Provision server.toml and a private control directory first. Start the server with:

```sh
vpn-server --config /etc/bproto/server.toml --datapath --control-socket /run/bproto/control.sock
```

The control directory must not be writable by group/others; the Unix socket is
mode 600. A systemd deployment needs a RuntimeDirectory and an ExecStart override
including the flag. This document does not claim that production systemd was tested.

Use a separate instance of the existing tools/config-agent/agent.py for TOML;
keep the old TLS/JSON instance on its existing target. Its private settings:

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 9444,
  "cert": "/etc/bproto/agent/server.pem",
  "key": "/etc/bproto/agent/server.key",
  "client_ca": "/etc/bproto/agent/panel-ca.pem",
  "target": "/etc/bproto/server.toml",
  "users_sync": {
    "inbound_id": 1,
    "server_binary": "/usr/local/bin/vpn-server",
    "control_socket": "/run/bproto/control.sock"
  },
  "health": ["/usr/local/bin/bproto", "--config", "/etc/bproto/health-client.toml", "connect", "--seconds", "1"],
  "stop": ["/usr/bin/systemctl", "stop", "bproto-server"]
}
```

The health client must use a dedicated operator-owned credential retained in
the static user section, not a normal device that may be revoked. This hook
checks authenticated service connectivity; use a real datapath probe too if
deployment policy requires it. No-op health/stop commands are not a deployment.

Run the agent as an identity that can access the control socket and manage the
config. A root agent preserves an existing target's uid/gid; mode remains 600.
Provision narrowly scoped permission for the fixed stop command. Do not grant
panel users arbitrary shell, command or path selection.

Panel configuration (paths/URLs below are illustrative, not credentials):

```text
BPROTO_KEY_SYNC_INBOUND=1
BPROTO_KEY_SYNC_AGENT_URL=https://agent.example.com:9444
BPROTO_CONFIG_AGENT_IDENTITY=/run/secrets/panel-agent-identity.pem
BPROTO_CONFIG_AGENT_CA=/run/secrets/agent-ca.pem
```

The identity PEM contains the panel client certificate and private key.
The endpoint is one fixed HTTPS origin; redirects and client-selected targets
are rejected. Only the configured CA is trusted. Certificates require correct
hostnames, validity and client/server usages. After repository migration, the
canonical project URL is https://github.com/bSECURITY-Team/bProto.

## Ownership and recovery

The agent appends a marked managed-users region at EOF, preserving operator
content and unrelated settings. Do not edit this region. An operator user with
the same uid as a managed user is an error, not silently overwritten. To migrate
previously copied panel entries, back up privately and remove those duplicate
static blocks during a planned provisioning window; retain the dedicated probe.
Explicit top-level empty users arrays may need normalization to array-of-tables
before initial provisioning; invalid candidates are rejected by the Rust parser.

The agent validates with the real vpn-server parser, writes a private journal,
atomically replaces TOML, requests local hot reload and verifies the keyed
runtime receipt plus the fixed health command. Only users may change through
hot reload; listeners, tag key, donor, TUN and admin settings require restart.
Updates do not reset retained session counters or anti-replay state.

Addition-only failures restore the old file/runtime and report rolled_back.
A removal failure keeps the safer candidate and recovery journal, invokes the
stop hook and reports rollback_failed. It never restores the removed PSK.
Fix the service/health failure and start it on the candidate config; retries
roll the journal forward. Stop/start orchestration is operator-owned; no
automatic service restart after the fail-closed stop is claimed.
Successful removals also sanitize the previous-file backup.

Keep .users-state, .users-journal and .users-lock with the target in a protected
directory. The journal can contain secret old/candidate bytes while recovering.
Never restore an old state file independently from the config: it carries the
revision/revocation barrier. Coordinate panel DB and agent-state restores.
This implementation is single-target, serial-worker. Concurrent workers from
several panel replicas and multi-server atomicity are not supported.
Snapshots are limited by the 64 KiB request boundary and 4096 explicit tombstones;
exceeding limits rejects delivery visibly. Tombstone compaction needs a future
coordinated epoch protocol; silently dropping old revocations is unsafe.

## Reproducible evidence

See [ORBIT-VALIDATION](ORBIT-VALIDATION.md) for this revision's actual checks.
Loopback e2e: build server/CLI/panel with --locked, then:

```sh
python3 -m unittest discover -s tests -p test_key_sync_e2e.py -v
```

Privileged lab: see [tools/key-sync-lab](../tools/key-sync-lab/README.md).
It uses separate server/client namespaces, kernel TUN, NET_ADMIN on both and
NET_RAW on the ICMP client, with no published ports. It verifies create/apply,
authenticated handshake, TUN packet round-trip, live-session revoke, dropped
packets and rejected new handshake. NAT/Internet, Android and production
systemd are outside that evidence.

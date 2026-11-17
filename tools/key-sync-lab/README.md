# Isolated key synchronization lab / Изолированная проверка ключей

This is a throwaway two-container Linux TUN lab, not a production smoke test.
Это временная лаборатория с отдельными server/client network namespaces.
Порты на хост не публикуются; ключи и БД находятся только в удаляемом volume.

Build the actual server, CLI and panel with locked dependencies. Copy stripped
binaries to keep Docker's VFS storage use bounded:

The runtime image contains dependencies only. Compose bind-mounts the selected
fixture files and stripped binaries read-only; the Docker build context excludes
everything. Rebuilding code therefore does not duplicate whole VFS image layers.

```sh
cargo build --locked -p vpn-server -p vpn-cli
cargo build --locked --manifest-path panel/backend/Cargo.toml
mkdir -p target/lab
strip --strip-all -o target/lab/vpn-server target/debug/vpn-server
strip --strip-all -o target/lab/bproto target/debug/bproto
strip --strip-all -o target/lab/panel panel/backend/target/debug/panel
chmod 755 target/lab target/lab/vpn-server target/lab/bproto target/lab/panel
chmod 644 tools/key-sync-lab/runner.py tools/config-agent/agent.py tools/connection_lab.py tests/test_key_sync_e2e.py
docker compose -p bproto-key-sync-test -f tools/key-sync-lab/compose.yaml up --build --abort-on-container-exit --exit-code-from server
docker compose -p bproto-key-sync-test -f tools/key-sync-lab/compose.yaml down --volumes
```

Use a unique project name, and always run down --volumes for that exact project,
including after failures. Never use host networking or mount the Docker socket.
Only the public fixture files/binaries above get public read permission. Do not
apply these modes to the private volume, keystores, configs or other credentials.
На обеих сторонах нужны TUN и NET_ADMIN; NET_RAW нужен ICMP-клиенту.
Image runtime is Debian trixie/glibc 2.41; compile binaries against a compatible
glibc. The lab does not install services or alter the host's network routes.

Checks / Проверки:

- Actual panel API → SQLite outbox → actual mTLS agent → actual native server.
- Authenticated CLI handshake for a newly issued key.
- Client kernel TUN setup and bidirectional ICMP to the server TUN address.
- Revocation via panel API; current TOML no longer contains the PSK.
- Existing live tunnel no longer passes ICMP; a fresh handshake is rejected.

The fixed operator health hook also performs an independent authenticated native
handshake. The file queue is a private lab fixture with an explicit command
allowlist; it is not part of the product control protocol.

Not tested / Не проверено: NAT/Internet forwarding, Android VpnService, IPv6,
production systemd, distributed panel replicas, cross-server failover or ECH.

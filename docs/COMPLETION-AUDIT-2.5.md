# Аудит и план дореализации / Completion audit and plan

[Русская версия / Russian version](COMPLETION-AUDIT-2.5.ru.md)

Дата / Date: 2026-11-17.
Baseline: tag `v2.5.0`, commit `d1081b3ad3dbe28d23c7df7cc3fafbc21179040b`.
Статус / Status: proposal for agreement; no feature implementation in this change.
Ветка / Branch: `docs/completion-audit-2.5`.

## Область и фактические проверки / Scope and executed checks

RU: Проверены TODO/FIXME/unimplemented и пути panel → agent, выдача/отзыв
ключей, серверная аутентификация/сессии, Android routing/fallback, транспортные
тесты, CI и текущая документация. Это целевой аудит шести целей, не полный
криптографический аудит. Исходники сначала прочитаны через GitHub, затем получен
полный чистый checkout; SHA тега и checkout совпадают.

EN: This targeted audit covers the six requested goals and their runtime/test
paths. It is not a complete cryptographic audit. GitHub reads and the subsequently
cloned checkout refer to the same release commit.

| Проверка / Check | Реально выполнено / Observed |
| --- | --- |
| `python3 -m unittest discover -s tests -p test_config_agent.py -v` | 7 passed from the release checkout |
| mTLS scope | Real TLS 1.3 loopback listener, temporary certificate, rejection without client certificate; service hooks mocked |
| Platform | Linux 6.18.57 x86_64, uid 1000 |
| Executor capabilities | CapEff=0; no /dev/net/tun; cargo absent |
| Docker | Read-only daemon version check succeeded: 29.9.2; no containers launched |
| VPN handshake / TUN / NAT / leak tests | NOT executed in this audit |
| Rust / Android / frontend builds and hosted CI | NOT executed or independently verified |

The sandbox initially denied socket creation; the unchanged agent suite passed
with the execution tool's approved escalation. Git clone also required that
execution context. No production endpoints, services or credentials were used.
Docker version availability does not prove usable TUN inside a container.
Historical results in other documents are historical evidence, not these results.

## Находки / Findings

1. **P0 — синхронизация не подключена / key synchronization not wired.**
   `panel/backend/src/inbounds.rs:566,865,965` writes SQLite for create/revoke.
   It does not call the agent. Delete, disable, inbound disable/delete and expiry
   must be covered too. `crates/vpn-server/src/admin.rs:23` checks configuration
   and returns success without starting an API; its KeysSync/Health remain TODO.
   The success-path admin unit test only checks `Ok(())`.
2. **P0 — конфликт модели ключей / credential cardinality mismatch.**
   Panel issues several PSKs with the same user_id/tag.
   `crates/vpn-core/src/tags.rs:48` stores one PSK per tag and silently replaces
   an earlier entry. `server.rs:407` replaces sessions by user_id.
   A naive snapshot loses valid keys; simultaneous devices need an explicit model.
   This is a compatibility decision before implementation.
3. **P0 — отзыв активной сессии не гарантирован / active revocation missing.**
   Removing a TagTable entry prevents new authentication, but established data
   traffic uses its existing session keys (`server.rs:199`), without checking
   table membership. The comment in tags.rs claiming next-packet revocation is
   stronger than this runtime path. Hot apply must evict revoked sessions,
   routes, leases and cached handshakes under a consistent update boundary.
4. **P0 — агент JSON, сервер TOML / agent format mismatch.**
   `tools/config-agent/agent.py` serializes version-1 config to JSON; its example
   target is a TLS-sidecar JSON file. Directly targeting server.toml is invalid.
   validate/reload/health are operator executables, not supplied VPN integration.
   There is no revision CAS, idempotency receipt, cross-process lock or
   crash-recovery journal. Two identical applies still reload and rotate backup.
5. **P0 — tag_key preflight отсутствует / no cross-plane key check.**
   `main.rs:347` in the panel compares a fingerprint with its own DB and
   recomputes tags. It does not compare with server.toml.
   `vpn-server --check-config` exits before building the user TagTable
   (`crates/vpn-server/src/main.rs:68,86`); malformed PSKs and duplicate
   credential identities need validation before that exit.
   Panel create-client's user/key writes are separate DB operations.
6. **P1 — APK release-подпись отсутствует / release signing absent.**
   build.yml publishes android-debug-apk even for releases.
   Android Gradle has a release build type but no release signing configuration.
   A debug→release signer change normally requires reinstall; encrypted Android
   Keystore storage cannot be assumed recoverable after uninstall.
7. **P1 — транспорты имеют частичные реальные тесты / transport evidence partial.**
   test_native_carriers.py contains native authenticated handshakes and wrong-PSK
   checks for TLS, HTTP3 and WSS, with the server started without --datapath.
   TLS/QUIC tests include hostname rejection; WSS also has token/framing checks.
   They are not full TUN or Android VpnService acceptance.
   test_ech.py checks ECH emission, hidden inner SNI, malformed/expired config
   and rejection by a non-ECH server. It does not test an accepting ECH server.
   A consistent failure matrix for untrusted/expired certificates, inner hostname,
   timeouts and midstream interruption is still needed.
8. **P1 — IPv6 datapath неполон / IPv6 forwarding incomplete.**
   IPv6 parsing exists, but leases, handshake address and server return routes
   are IPv4. Android captures ::/0 and stops if capture fails.
   However Session::seal_ip is family-agnostic and ServerNode::handle returns
   decrypted IP bytes for writing to TUN: do not infer an explicit bidirectional
   IPv6 drop gate from the Android comment. Egress/leak behavior needs a real test.
   Android's comment about retrying IPv4-only is stale: the current code stops.
9. **P1 — failover отсутствует, rebinding существует / failover vs rebinding.**
   Android tries candidates in order and stops after pump returns.
   ACK RTT metrics exist; ranking and established-session reconnect are absent.
   server.rs:702 tests authenticated UDP source-address rebinding and replay
   rejection. This is useful existing behavior, not cross-server session migration.
10. **P1 — доменные правила отсутствуют / domain rules absent.**
    RoutingPolicy.kt only accepts IPv4 routes, DNS literals and bypass_apps.
    Domain decisions require a resolver/IP attribution model; CDN/shared IPs and
    application DoH prevent reliable domain classification from IP alone.
11. **Другие явные заглушки / other explicit stubs.**
    masquerade/mod.rs:125 and masquerade/hello.rs:55 return Error::Unimplemented.
    censor_gets_real_site.rs:61 is ignored and calls unimplemented!.
    Non-Linux TunDevice::open returns an explicit unsupported error.
    Fingerprint enum values do not prove working browser fingerprints.
12. **Документация / documentation drift.**
    ORBIT-VALIDATION.md reflects an older stage and says disguise is unimplemented;
    AUDIT.md appends later transport work to older tables.
    README's release-signing row still says “Not in v1.0.0”.
    Consolidate current status, platform, capabilities and evidence per feature;
    keep old results explicitly labeled by revision and date.

## Предлагаемая матрица / Proposed evidence matrix

This is an audit classification, not a promotion of any feature to completed.
“Implemented” below always carries the stated verification boundary.

| Возможность / Feature | Статус / Status | Граница / Evidence boundary |
| --- | --- | --- |
| Agent JSON apply/health/rollback + mTLS | implemented | 7 tests passed; service commands mocked; crash recovery absent |
| Automatic panel → VPN keys | not wired | No create/revoke → agent → live server path |
| Linux native handshake | implemented | Source + existing tests; not rerun here |
| Linux TUN/NAT | requires privileges | Historical lab record; not rerun here |
| TLS/HTTP3/WSS | implemented (experimental scope) | Existing handshake/carrier tests; full TUN/device acceptance open |
| Successful ECH acceptance | not implemented in supplied server | Client emission/rejection tests exist |
| Native IPv6 forwarding | not implemented | IPv4 lease/return routing; fail-closed policy requires leak evidence |
| RTT ranking / live failover | not implemented | Same-server authenticated rebinding already exists |
| Domain routing | not implemented | CIDR/DNS/app rules only |
| Android release-signed CI artifact | not implemented | Debug artifact currently published |
| Browser fingerprint construction | not implemented | Explicit Unimplemented paths remain |
| Guaranteed evasion / invisibility | not claimed | No such acceptance criterion |

## План цели 1 / Goal 1 design

RU: Использовать существующий агент и его mTLS, фиксированный адрес и
операторские команды. Не писать второй удалённый control-plane протокол.
EN: Extend the existing agent; retain mTLS, fixed destinations and operator-owned
commands. Do not replace it with a new remote management service.

1. **Модель / model.** Agree handling of multiple keys per uid first. Preferred:
   bounded PSK candidates per existing routing tag, selected by the existing
   handshake MAC, plus internal credential identity for session revocation.
   Preserve existing wire uid/tag, import URIs and crypto primitives.
   Decide whether independent concurrent device sessions are in this first PR;
   they also require changing lease/session ownership, not only TagTable lookup.
   Bound candidate counts and unauthenticated verification work. Never silently
   choose “last/newest PSK”. Alternative restrictions must reject conflicts
   explicitly and include a migration plan for existing multi-key users.
2. **Desired/applied state.** Add additive SQLite migrations for per-target desired
   revisions, durable outbox and confirmed applied revision. Create/revoke/delete/
   disable operations update state and outbox in one SQLite transaction. Worker
   retries reconcile the latest desired state, including expiry. Remote subscription
   credentials are never pushed to local servers. Map inbounds to fixed
   operator-provisioned agent/service targets, not user-controlled URLs.
3. **Agent compatibility.** Keep version-1 JSON/TLS operations unchanged. Add an
   explicit versioned users-snapshot operation and TOML target adapter to the
   same agent, rejecting unknown versions/fields. The target/path/commands are
   fixed operator settings. A separate instance of the same agent may manage
   server.toml while the old instance continues managing TLS JSON.
   Only the managed users portion may change; preserve unrelated TOML settings,
   comments and legacy unmanaged users under an agreed ownership policy.
4. **Preflight.** Check current config and target identity, supported schema,
   all credential lengths/duplicates and expected base revision. Prove matching
   tag_key before any mutation via a nonce-bound domain-separated HMAC proof
   computed from each side's existing key; do not transmit/log tag_key.
   Reuse HMAC-SHA256, require the full proof, bind target/revision/challenge,
   expire challenges and compare in constant time. This is a proposed control-
   plane proof, not a change to the VPN handshake.
5. **Apply/health/rollback.** Use a target lock, private staged TOML, validation by
   the actual Rust parser, durable recovery journal and atomic replacement with
   fsync. Package real validation/reload/health executables. Prefer hot reload
   of user credentials to restarting all tunnels. Local acknowledgement must
   identify the exact applied revision; define a restricted local IPC/status
   mechanism for the agent rather than claiming the existing gRPC stub works.
   Update runtime credentials and revoked-session state consistently.
   Health must verify the exact runtime revision and an authenticated exchange,
   not only PID, port, command exit or file contents.
6. **Idempotency/recovery.** Same target/revision/content gives the same receipt
   without reloading or replacing the backup; same revision/different content
   conflicts; stale revisions cannot overwrite newer state. Handle lost HTTP
   response after commit by querying the durable receipt. Recovery after crashes
   reconciles journal, disk and runtime before accepting another mutation.
   Use a keyed content identifier where credential-bearing content needs an ID.
7. **Revocation semantics.** UI distinguishes pending, applied, rolled_back and
   rollback_failed, with desired/applied revisions. Do not claim “revoked on
   server” while unreachable. Once confirmed, a revocation must not be undone by
   a retry, old backup or stale snapshot: durable revocation tombstones/revision
   barriers constrain rollback. If recovery cannot honor revocation, fail closed
   and expose degraded health. Availability versus urgent revoke is a decision.
8. **Distributed boundary.** SQLite and a remote service cannot be one ACID
   transaction. Promise durable desired state + observable convergence and
   transactional per-agent apply, not instantaneous global atomic commit.
   Do not hold a SQLite write transaction across mTLS calls. Multi-server
   application has per-target status, never an unqualified “all applied”.

## Проверки цели 1 / Goal 1 acceptance tests

- Unit: TOML preservation, schema rejection, credential validation, tag mismatch,
  duplicate IDs/keys, candidate limits, CAS/idempotency and zero secret output.
- Integration: actual panel API + temporary SQLite → actual mTLS agent → actual
  vpn-server → actual CLI authenticated handshake and encrypted packet exchange.
  Revoke through API; require failed fresh handshake and no further traffic
  on the revoked live session. Another user's established session keeps working.
- Revoke must be absent from the current managed TOML and runtime auth set;
  tests also cover create-key, delete-key/client, disable and expiry.
- Inject validator/reload/health failures, service death, response loss, duplicate/
  reordered delivery and crashes around file replacement/runtime commit. Verify
  recovery and that rollback cannot resurrect a confirmed revoked credential.
- mTLS: missing/untrusted/expired client cert, untrusted/wrong-name server cert,
  redirects, unknown target and payload limits.
- Privileged acceptance: separate Linux namespaces/VMs with TUN, NET_ADMIN;
  NET_RAW only for capture. Use synthetic destinations, a unique lab project,
  private throwaway keys/certs and captures. Assert bidirectional packets and
  no traffic from revoked sessions. Never use production smoke testing.
- Record SHA, commands, platform, capabilities, timeouts, packet evidence and
  exact exclusions in ORBIT-VALIDATION.md before promoting the feature status.

## Очередь веток и PR / Branch and PR sequence

The requested priority order is retained. Split each goal into reviewable atomic
commits (contracts → runtime → tests → RU/EN docs), with test results attached
to its PR. This audit branch precedes implementation; no implementation PR yet.

| Order / branch | Scope and acceptance |
| --- | --- |
| 1. feat/key-sync-mtls | Resolve credential model; outbox; versioned agent TOML adapter; hot runtime apply and revocation; crash recovery; create/apply/revoke handshake + TUN gates |
| 2. ci/android-release-signing | Protected tag/manual release job using repository secrets, private temporary keystore, signing verification and signer fingerprint check, cleanup; fail if secrets absent, never substitute debug signing |
| 3. test/transport-e2e | TLS/HTTP3/WSS real client/server + TUN; accepting ECH terminator; untrusted/expired/wrong-host certs, disabled ECH, wrong inner name, timeouts, interruption, no downgrade; Android runtime separately |
| 4. feat/ipv6-datapath | Default deny gate, optional dual-stack leases/routes and negotiated address extension preserving legacy handshake; ICMPv6/PMTU, DNS/AAAA and leak tests including failed capture/reconnect |
| 5. feat/rtt-ranking-migration | ACK-derived smoothed RTT, freshness/hysteresis and failed-path backoff; same-server transport migration preserves session counters/replay and TUN/IP; TCP continuity measured |
| 6. feat/domain-routing | Resolver integration, exact/suffix rules, TTL/CNAME/IP provenance; conflicts/shared-CDN policy; versioned subscription delivery with explicit old-client refusal |

Android signing: document secure offline key backup and signer ownership.
Debug→release transition requires user-visible export of subscription references/
profiles before reinstall, then reimport; never log them. An in-app export may be
needed because Keystore state is lost on uninstall. APK signer rotation uses
supported signing lineage/platform capabilities where available; legacy devices
may require reinstall. Test both supported upgrade and reinstall paths using
throwaway signing identities. A keystore merely present in CI is not proof that
an upgrade from an installed APK works.

Transport acceptance: a local controlled ECH-capable HTTP3 frontend must actually
decrypt ECH and serve the carrier; publishing an ECHConfigList alone is insufficient.
Record each runtime separately (Rust, Python carrier, Android device/emulator).

IPv6: raw encrypted packet carriage alone is insufficient. Add leases, reverse
routing, source ownership checks, forwarding/firewall policy, PMTU and leak gates.
Prefer a lab routed prefix; agree production routing versus NAT66 separately.
Old clients must retain their current formats and default IPv6 deny behavior.

Failover: seamless cross-server TCP continuity requires preserved tunnel addresses,
egress identity and routing/conntrack state; independent servers do not provide it
today. Do not export session keys to implement an unreviewed HA design.
Implement and claim only the tested same-server migration scope initially;
cross-server reconnect may interrupt TCP and remains explicitly unclaimed.

Domain routing proposal for agreement: explicit app bypass remains an Android
OS-level exclusion; domain block beats allow; exact match beats suffix; longer
suffix beats shorter; equal-priority conflicting actions reject the update.
Domain allow/bypass must not broaden to every name sharing a CDN address.
Conservative tunnel routing when attribution is ambiguous; retain IP provenance
until all referencing DNS records expire. Account for CNAME/AAAA, TTL limits,
cache replacement, negative answers and existing-flow stability. System-wide
DoH/DoT cannot be classified reliably without a separate policy.
Deliver domain-bearing rules under an explicit supported schema/capability;
never silently discard them for schema-1 clients.

## Решения до реализации / Decisions before implementation

1. Keep priorities 1→6 and accept the first milestone as key-sync only?
2. Multiple keys per user: support existing uid/tag with bounded PSK candidates
   and credential-aware sessions, or explicitly restrict to one active key with
   migration? Can devices connect concurrently?
3. Ownership: does the panel own all [[users]] on a target, or preserve an
   operator-managed subset? Which inbounds map to each logical target?
4. Is key hot reload required to preserve other users' sessions? Recommended yes.
   Confirm immediate live-session revocation and fail-closed recovery semantics.
5. Single server first or multi-server convergence in the initial milestone?
   Recommended single target with a schema that permits future target IDs.
6. Lab: extend the existing isolated Docker/TUN lab or use dedicated VMs?
   Need actual NET_ADMIN/TUN availability inside the lab; no production testing.
7. Later milestones: who owns the permanent Android signing key; which device
   API levels are supported; IPv6 prefix/routing model; controlled accepting ECH
   frontend; domain DNS/DoH policy; same-server versus cross-server migration?
   These decisions need not block the independent key-sync implementation.

RU: Запрашиваются решения по процессу пользователя («сначала план и согласование»),
а не дополнительное разрешение, навязанное навыком. Секреты в чат не присылать.
EN: Agreement is requested because the user explicitly required a plan before
implementation. No skill adds an approval requirement. Do not send secrets here.

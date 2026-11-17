# Orbit implementation validation

## PR synchronization with current main / Подготовка PR — 2026-11-17

The target main advanced to 1d95122 (merged upstream PR #4) after the original
credential implementation. The key-sync branch now integrates that main:
upstream TCP return paths, shape configuration and startup are preserved, and
the credential regression uses the updated handle(..., tcp) API.

Executed again on the integrated code: full locked workspace 163 passed,
one unchanged ignored donor skeleton; workspace clippy with warnings denied
passed. Real panel/mTLS/native loopback create/apply/revoke passed (9.486 s),
and the two-namespace kernel TUN/live-revoke test passed (13.399 s). The Linux
capability and non-production limits below still apply. No unrelated network,
Android-device or Internet-forwarding acceptance is inferred from this merge.

Upstream push, GitHub integration branch creation and personal-fork creation
each returned HTTP 403. No GitHub PR has been created. The following original
implementation record remains evidence for its explicitly named older baseline.

## Credential synchronization / Синхронизация ключей — 2026-11-17

Baseline: v2.5.0/d1081b3. Implementation branch: feat/3.0-key-sync.
Final server runtime source under test: af76edf (HELLO dedup preserved).
Repository moved to https://github.com/bSECURITY-Team/bProto; HEAD is unchanged.
Publication currently fails with HTTP 403 via both Git and GitHub integration.
These are local results, not claims of hosted CI success or a 3.0.0 release.

| Executed check / Выполненная проверка | Result / Результат |
| --- | --- |
| Core/server locked tests | 133 passed; 1 pre-existing ignored donor skeleton remains ignored |
| Full locked Rust workspace, including hot-reload HELLO dedup regression | 148 passed, 1 legacy ignored test |
| Core/server clippy, all targets, warnings denied | Passed |
| Full workspace clippy, all targets, warnings denied | Passed; existing Cargo manifest advisories are still emitted by Cargo 1.100 |
| Panel locked tests | 65 passed |
| Panel clippy, all targets, warnings denied | Passed on final ownership-aware schema |
| Agent v1 tests | 7 passed, including real loopback mTLS |
| Users adapter tests | 9 passed: proof mismatch, revision conflict, rollback, crash recovery, permanent revoke vs reversible disable, static-ownership conflicts |
| Agent combined statement coverage | 73% (328 statements); existing 70% gate retained |
| Actual panel → mTLS agent → server → CLI | Create/apply, authenticated handshake, revoke, rejected handshake passed; final schema run 9.459 s |
| Separate-container kernel TUN acceptance | Passed, final run 13.399 s: handshake, TUN ICMP round-trip, live revoke, no subsequent ICMP and rejected fresh handshake |
| Frontend TypeScript + Vite production build | Passed; direct local compiler/build invocation used because executor pnpm wrapper refused esbuild install scripts |
| Installer contracts + shell syntax | 5 passed; download URLs use the new repository |

Platform: executor Linux 6.18.57 x86_64; Rust 1.100.0; Docker 29.9.2.
The executor itself has CapEff=0 and no TUN. The two-container Debian trixie lab
has independent network namespaces, /dev/net/tun and NET_ADMIN on each side;
the ICMP client also has NET_RAW. No host networking, published ports or
production service was used. All lab keys/DB live in a private temporary volume
removed after validation. The health hook performs a separate authenticated
native handshake. Full product flow includes actual Rust binaries and SQLite;
the transaction failure unit tests mock service operations explicitly.

Executor-specific lab corrections: Docker VFS exhausted disk when binaries were
copied into repeatedly rebuilt image layers. The final image contains runtime
dependencies only; selected public fixtures/binaries are mounted read-only.
The executor's umask 077 required explicit read/traverse modes for those public
files and their binary directory. Secret volume/config/key modes were not widened.
The corrected final lab passed without adding DAC capabilities.

Implemented scope: one configured inbound, fixed mTLS target, durable SQLite
desired/applied state, versioned TOML adapter, keyed tag-key consistency proof,
hot credentials, sibling device sessions and live revocation. See
[KEY-SYNC EN](KEY-SYNC.md) / [RU](KEY-SYNC.ru.md) for limits, ownership and recovery.

Not verified: production systemd, public-network NAT/Internet forwarding,
Android device, multi-replica panel, multi-server convergence, successful ECH
acceptance, IPv6 leak prevention or cross-server TCP continuity.
Runtime target receipts alone do not prove arbitrary Internet forwarding.
Post-stop recovery requires the operator to start the corrected service;
automatic service restart and tombstone epoch compaction are not implemented.

## Android release signing preparation / Подготовка release-подписи

Branch: ci/3.0-android-release-signing, stacked on the credential branch.
Added environment-based Gradle signingConfig and a trusted-tag workflow consuming
native libraries from the same run. Release publication requires android-release-apk,
successful apksigner verification and the configured public certificate fingerprint.
Missing secrets never cause a debug fallback. Keystore preparation uses mode 600
and exclusive creation; cleanup is unconditional.

Executed: four artifact-gate tests passed, checking missing/malformed keystore,
private permissions, overwrite rejection, verifier failure, mismatched signer and
multiple signers. These tests use subprocess fixtures, not a real signed APK.
Workflow YAML parsed successfully; release depends on the signing job.
NOT executed: Gradle release compilation, real signing, hosted Actions, installed
Android upgrade, signer rotation or debug-to-release reinstall/reimport.
These remain acceptance gates, not completed features.
Procedures: [EN](ANDROID-SIGNING.md) / [RU](ANDROID-SIGNING.ru.md).

## Historical Orbit baseline / Исторические проверки

Recorded on 2026-11-16 in a prior shared Linux development environment. The Orbit
series comprises 100 commits after baseline `7fcf5c6`; each was pushed to `main`.

## Implemented workflow

* Responsive panel navigation, workspace header, sign-in and routing editor.
* Authenticated subscription routing settings, transactional updates and
  versioned JSON exports. Text/base64 formats retain their key-only format.
* Android globe connection control, server picker, ordered authenticated
  fallback, JSON/text/base64 imports and per-profile routing overrides.
* Android Keystore encrypted profile storage, explicit profile removal,
  DNS capture routes, application exclusions and fail-closed IPv6 capture.
* CI builds Linux/panel and Android, runs Android contract tests and verifies
  all eight JNI functions for all three Android ABIs.

## Executed checks

| Check | Observed result |
| --- | --- |
| Rust workspace tests, `cargo test --locked --workspace` | Passed; default ignored tests remain ignored |
| Workspace clippy, all targets, warnings denied | Passed |
| JNI feature clippy, all targets, warnings denied | Passed |
| JNI feature tests | 6 passed |
| Panel backend tests | 62 passed, 0 failed |
| Rust formatting for workspace and separate panel backend | Passed |
| Frontend TypeScript build and Vite production build | Passed |
| Android `testDebugUnitTest` | 14 passed, 0 failed |
| Android `assembleDebug` | Passed with native libraries packaged |
| Native release builds | arm64-v8a, armeabi-v7a, x86_64 passed |
| APK contents | `libbproto.so` present for all three ABIs |
| JNI export inspection | All eight required exports present for every ABI |
| Native loopback demo with `RUST_LOG=error` | Authenticated handshake, assigned address `10.66.0.2`, session completed |
| Shell syntax and Git whitespace checks | Passed |

The demo initially timed out because its readiness check depended on an info
log hidden by the inherited log filter. The demo now explicitly enables server
info events while preserving the caller's other filters. The corrected demo
was rerun successfully.

## Limits of this evidence

The APK has not been exercised on a physical device or emulator in this task.
The loopback demo does not exercise TUN, NAT, system DNS or Internet forwarding.
The debug APK uses a development signing key, not a persistent release key.
No target-network censorship or allowlist test was performed. Ordered fallback
selects the first reachable authenticated endpoint; it neither measures the
fastest server nor reconnects an established tunnel automatically after failure.
Routing cannot make a blocked server reachable. Transport disguise and guaranteed
allowlist bypass are not implemented. Refer to `ROUTING-RU.md` for details.

These are historical results. GitHub Actions results must be checked on
the final push; local validation does not assert that a hosted workflow passed.

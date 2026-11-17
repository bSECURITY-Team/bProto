# 3.0 acceptance state / Состояние приёмки 3.0

This branch is development toward 3.0.0, not a completed or published release.
Версия 3.0.0 не объявлена и release tag не создан. Текущая базовая версия кода — 2.5.0.

Canonical repository: https://github.com/bSECURITY-Team/bProto.
The key-sync and Android signing work has been merged into `main`. PR #6 merged
credential synchronization; PR #5 merged Android release signing. PR #7 was a
duplicate stacked draft and was closed after confirming its changes were covered
by #5. Main HEAD at the last check is `0d44a597`.

## Current deliverables / Текущие результаты

| Goal / Цель | State / Статус | Evidence and open gate / Проверка и открытая граница |
| --- | --- | --- |
| Panel → server credentials | implemented, opt-in single inbound | Actual panel/mTLS/server/CLI, kernel TUN and live revoke passed; operator provisioning and production systemd remain outside verification |
| Android release signing | CI/configuration prepared; not validated as distribution | Four gate tests passed; real signing secrets, hosted Gradle/signing run and device migration are required |
| TLS/HTTP3/WSS/ECH stabilization | acceptance incomplete | Existing handshake tests reviewed; transport-specific TUN/device failure matrix and accepting ECH server are still open |
| Native IPv6 | not implemented | IPv4 leases/reverse routing remain; explicit default-deny datapath gate and leak tests still needed |
| RTT ranking/live migration | not implemented | Existing authenticated rebinding retained and tested by workspace suite; no ranking or cross-server TCP continuity claim |
| Domain routing | not implemented | Existing CIDR/DNS/app rules retained; resolver provenance/conflicts/versioned domain schema still needed |

No transport disguise, invisibility or censorship-evasion guarantee is claimed.
Обещания обхода блокировок и незаметности не добавлялись.

## Validation / Проверки

Integrated full workspace: 163 passed, one unchanged ignored donor skeleton. Panel: 65
passed. Agent: 7 legacy and 9 users-adapter tests passed, 73% statement coverage
with the original 70% gate retained. Full workspace and panel clippy passed.
The final native server includes the hot-reload HELLO-dedup regression fix.
See [ORBIT-VALIDATION](ORBIT-VALIDATION.md) for exact platform and capability scope.

## Remaining work / Следующая работа

The hosted `main` workflow failed in the Linux panel job because the key-sync
e2e step was pointed at `panel/backend/target/release/panel` without building
that release binary. The local correction explicitly runs the release build and
the same e2e then passes. Re-run the hosted workflow after publishing this fix.
Other open gates are actual Android signing/upgrade validation, transport failure
matrix and an accepting ECH frontend, native IPv6 forwarding/leak tests, RTT
selection and live-session migration, and DNS-attributed domain rules.

For cross-server uninterrupted TCP, first design preserved tunnel/egress
addresses and routing/conntrack ownership. Independent server reconnect alone
does not satisfy that goal. For domain routing, agree shared-CDN/DoH ambiguity
and schema-1 behavior before wiring a resolver.

Права GitHub восстановлены, изменения уже находятся в `main`. Release tag
откладывается до прохождения CI и оставшихся gates. Signing secrets задаются в
GitHub settings; не передавайте их в чат.
Количество коммитов не используется как доказательство готовности: пустые коммиты
и искусственное дробление ради числа 500 не создавались. Изменения уже в `main`;
CI и незавершённые цели остаются явно открытыми.

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
| Android release signing | implementation and ephemeral-signing CI smoke | PR #8 hosted smoke builds/verifies a release APK with a generated two-day key; permanent repository signer, real trusted-tag release and device upgrade/reimport remain unverified |
| TLS/HTTP3/WSS/ECH stabilization | partial; release gate open | Hosted isolated TLS/HTTP3/WSS checks pass; ECH emission/rejection is checked, but no accepting ECH server, full failure matrix or Android device datapath run |
| Native IPv6 | not implemented; IPv6 forwarding absent | IPv4 leases/reverse routes only; IPv6 packets are captured/dropped when platform capture succeeds; forwarding and leak tests are open |
| RTT ranking/live migration | not implemented | Existing authenticated same-server rebinding only; no RTT ranking, cross-server migration, or TCP continuity claim |
| Domain routing | not implemented | CIDR/DNS/app bypass only; DNS provenance, CDN updates, conflict policy and subscription schema remain open |

No transport disguise, invisibility or censorship-evasion guarantee is claimed.
Обещания обхода блокировок и незаметности не добавлялись.

## Validation / Проверки

Integrated full workspace: 163 passed, one unchanged ignored donor skeleton. Panel: 65
passed. Agent: 7 legacy and 9 users-adapter tests passed, 73% statement coverage
with the original 70% gate retained. Full workspace and panel clippy passed.
The final native server includes the hot-reload HELLO-dedup regression fix.
See [ORBIT-VALIDATION](ORBIT-VALIDATION.md) for exact platform and capability scope.

## Remaining work / Следующая работа

The pre-existing `main` workflow failed in the Linux panel job because the
key-sync e2e step used a release binary that CI had not built. PR #8 adds that
build and an ephemeral Android release-signing smoke job. Hosted PR run
44152774468 confirms the Linux/panel key-sync e2e, isolated kernel TUN lab,
Android three-ABI build and installer/QUIC checks pass. The ephemeral signed APK
job is still pending at this documentation revision; the push workflow skipped
it because it only runs for PRs and main. This CI evidence does not close the
remaining product acceptance gates.

Open release gates: trusted permanent Android signer and supported-device
upgrade/reimport check; full TLS/HTTP3/WSS/ECH failure matrix plus an accepting
ECH frontend; IPv6 forwarding/leak tests; RTT ranking and bounded failover
behavior; domain rules with resolver/CDN provenance and subscription semantics.

For cross-server uninterrupted TCP, first design preserved tunnel/egress
addresses and routing/conntrack ownership. Independent server reconnect alone
does not satisfy that goal. For domain routing, agree shared-CDN/DoH ambiguity
and schema-1 behavior before wiring a resolver.

PR #8 contains the CI fix and is not merged yet. The release tag remains
withheld until the acceptance gates above pass. Set signing secrets in GitHub
settings; never send them in chat.

В PR #8 добавлено исправление CI; PR пока не слит. Тег релиза не создаётся до
прохождения указанных проверок. Signing secrets задаются в GitHub settings;
не передавайте их в чат.
Количество коммитов не используется как доказательство готовности: пустые коммиты
и искусственное дробление ради числа 500 не создавались. Изменения уже в `main`;
CI и незавершённые цели остаются явно открытыми.

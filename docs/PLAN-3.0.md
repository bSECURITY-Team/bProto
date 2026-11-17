# 3.0 acceptance state / Состояние приёмки 3.0

This branch is development toward 3.0.0, not a completed or published release.
Версия 3.0.0 не объявлена и release tag не создан. Базовая версия остаётся 2.5.0.

Canonical repository: https://github.com/bSECURITY-Team/bProto.
The repository transferred without changing its d1081b3 baseline. Git and the
GitHub integration can read it but writes return HTTP 403. No implementation
commits or PRs have been published there from this workspace.

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

## Branches and validation / Ветки и проверки

- feat/3.0-key-sync: authentication model, private server IPC, existing-agent TOML
  adapter, durable outbox/recovery, real TUN acceptance, UI and RU/EN docs.
- ci/3.0-android-release-signing: stacked on the first branch; signing secrets
  configuration, artifact identity gate, CI publication dependency and RU/EN
  signer rotation/debug migration procedures.

Full workspace: 148 passed, one unchanged ignored donor skeleton. Panel: 65
passed. Agent: 7 legacy and 9 users-adapter tests passed, 73% statement coverage
with the original 70% gate retained. Full workspace and panel clippy passed.
The final native server includes the hot-reload HELLO-dedup regression fix.
See [ORBIT-VALIDATION](ORBIT-VALIDATION.md) for exact platform and capability scope.

## Remaining work / Следующая работа

Resume the prioritized implementation sequence after reviewing/publishing the
first deliverables. Do not mark later goals complete based on names or unit
fixtures. Continue with actual signing validation when repository secrets and
hosted execution are available, then the isolated transport failure matrix and
an accepting ECH frontend, dual-stack leases/routing/leak tests, bounded RTT
selection and same-server migration, and finally DNS-attributed domain rules.

For cross-server uninterrupted TCP, first design preserved tunnel/egress
addresses and routing/conntrack ownership. Independent server reconnect alone
does not satisfy that goal. For domain routing, agree shared-CDN/DoH ambiguity
and schema-1 behavior before wiring a resolver.

Публикация заблокирована конкретным 403, а не отсутствием разрешения пользователя.
Signing secrets задаются в GitHub settings; не передавайте их в чат.
Количество коммитов не используется как доказательство готовности: пустые коммиты
и искусственное дробление ради числа 500 не создавались. Проверенные изменения
сохраняются локально; незавершённые цели остаются явно открытыми.

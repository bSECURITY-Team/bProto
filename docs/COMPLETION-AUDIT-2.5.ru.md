# Аудит bProto 2.5.0 и согласование реализации

Дата: 2026-11-17. Тег `v2.5.0` и checkout:
`d1081b3ad3dbe28d23c7df7cc3fafbc21179040b`.
[Подробный план и реестр доказательств на английском](COMPLETION-AUDIT-2.5.md).
Статус: предложение до реализации. Изменены только документы.

> **Примечание о текущей ветке `arena/901cacf6-bproto` (не относится к baseline аудита).**
> Причина «подключено, но все запросы таймаутят» исправлена в коде: capture
> `::/0` без IPv6-адреса убран; перехваченный IPv6 получает корректный ICMPv6
> «no route»; при отказе прошивки от IPv6 capture туннель работает IPv4-only
> с явным предупреждением об утечке; ошибки отправки пакета больше не убивают
> pump; статус «connected» публикуется только после `pumpActive()`; все UDP/TCP
> и carrier-сокеты защищаются до connect и повторно при смене сети. Полный
> нативный IPv6 forwarding по-прежнему **не реализован**. Реального Android
> устройства и живого сервера в песочнице не было, поэтому gate по device/e2e
> ниже остаётся открытым. Утверждения об отказе подключения при IPv6 capture и
> устаревшие заметки про retry описывают старый baseline, а не текущую ветку.

## Что проверено

Проведён целевой аудит TODO/FIXME/Unimplemented и runtime-путей шести целей:
панель, агент, выдача и отзыв ключей, серверные сессии, Android, IPv6, routing,
транспорты и CI. Это не полный аудит криптографии.

Из подтверждённого checkout выполнено:
`python3 -m unittest discover -s tests -p test_config_agent.py -v` — 7 passed.
Есть реальное mTLS-соединение на loopback и отказ без клиентского сертификата;
validate/reload/health сервиса подменены. Это не VPN handshake и не datapath.
Песочница сначала запретила сокет; неизменённый тест прошёл в разрешённом
контексте исполнения с эскалацией.

Среда: Linux 6.18.57 x86_64, uid 1000, CapEff=0, нет cargo и /dev/net/tun.
Read-only запрос к Docker daemon успешен, версия 29.9.2. Контейнеры не запускались;
наличие TUN внутри Docker не проверено. Rust/Android/frontend не собирались.
VPN handshake, TUN/NAT, IPv6-утечки, успешный ECH и hosted CI здесь не проверялись.
Исторические проверки в репозитории не выдаются за результаты этого аудита.
Production не использовался.

## Находки и риски

| Приоритет | Находка | Доказательство |
| --- | --- | --- |
| P0 | create/revoke меняют SQLite, но не вызывают агент | inbounds.rs:566,865,965 |
| P0 | Серверный admin API — заглушка: проверяет параметры, не запускает listener | vpn-server/src/admin.rs:23 |
| P0 | Панель выдаёт несколько PSK на uid/tag; сервер хранит один и перезаписывает предыдущий | vpn-core/src/tags.rs:48 |
| P0 | Повторное подключение того же uid заменяет его сессию; независимые устройства требуют решения | vpn-core/src/server.rs:407 |
| P0 | Удаление TagTable запрещает новый handshake, но не отзывает существующие session keys | vpn-core/src/server.rs:199 |
| P0 | Агент пишет JSON; server.toml требует отдельного адаптера | tools/config-agent/agent.py |
| P0 | Нет revisions/CAS, receipt, журнала восстановления и межпроцессного lock; повторный apply снова reload | tools/config-agent/agent.py |
| P0 | Сверки tag_key панели с сервером нет; sync_tags проверяет только собственную БД | panel/backend/src/main.rs:347 |
| P0 | --check-config завершается до построения TagTable; валидация PSK неполна | vpn-server/src/main.rs:68,86 |
| P0 | Создание пользователя и ключа — отдельные операции БД | panel/backend/src/inbounds.rs:566 |
| P1 | CI публикует debug APK; release signingConfig отсутствует | build.yml, Android build.gradle.kts |
| P1 | TLS/HTTP3/WSS имеют тесты настоящего handshake, но без серверного --datapath | tests/test_native_carriers.py |
| P1 | ECH проверен на emission/rejection; принимающий ECH сервер отсутствует | tests/test_ech.py |
| P1 | IPv6 parsing есть, адреса/обратная маршрутизация IPv4; явный drop gate не доказан | ip.rs, session.rs:159, server.rs:199,276 |
| P1 | Android перебирает серверы по порядку; нет ранкинга RTT и возврата к выбору после pump | BprotoVpnService.kt |
| P1 | Есть безопасный UDP rebinding после аутентификации; это не перенос на другой сервер | server.rs:702 |
| P1 | Только IPv4 CIDR/DNS/bypass_apps, доменного движка нет | RoutingPolicy.kt |

Отдельные заглушки: masquerade/mod.rs:125 и masquerade/hello.rs:55 возвращают
Error::Unimplemented; censor_gets_real_site.rs:61 игнорируется и вызывает
unimplemented!. Non-Linux TUN явно возвращает unsupported.
Имена browser fingerprint не доказывают готовую генерацию ClientHello.

Android останавливается при невозможности IPv6 capture; комментарий про retry
IPv4-only устарел. При этом seal_ip не проверяет семейство, сервер передаёт
расшифрованные IP-байты в TUN. Поэтому нельзя считать отсутствие обратного IPv6
маршрута доказательством политики drop или отсутствия утечек.

ORBIT-VALIDATION.md отражает старую стадию, AUDIT.md содержит исторические таблицы
с последующими дополнениями, README упоминает отсутствие release-подписи
«в v1.0.0». Нужна единая актуальная матрица с SHA, платформой и границами.

## План синхронизации через существующий mTLS-агент

1. Согласовать несколько ключей на uid. Предпочтение: ограниченный набор PSK
   под существующим tag, проверка существующим MAC, внутренняя идентичность
   credential для отзыва. Примитивы и uid/tag в старых URI не меняются.
   Одновременные устройства требуют также привязки leases/sessions к credential.
   Ограничить CPU/число кандидатов. Нельзя молча выбирать последний ключ.
2. Добавить additive migrations: desired revision, applied revision, outbox,
   target mapping. Изменение ключа и outbox — одна транзакция SQLite. Покрыть
   create/revoke/delete/disable, inbound changes и expiry. Не отправлять ключи
   чужих remote subscriptions на собственный сервер.
3. Сохранить agent v1 JSON/TLS. Добавить явно версионированную users-snapshot
   операцию и TOML-адаптер в тот же агент; неизвестные версии/поля отклонять.
   Адрес агента, target/path и команды задаёт оператор. Для TOML и TLS JSON
   можно использовать отдельные экземпляры того же агента. Сохранить несвязанные
   TOML-настройки, комментарии и согласованную unmanaged-область пользователей.
4. До записи сверить target, base revision, PSK и конфликты. Совпадение tag_key
   доказать полным HMAC-SHA256 с domain separation, nonce, target и revision:
   обе стороны считают proof своим существующим ключом, ключ не передаётся.
   Challenge ограничен по времени, сравнение constant-time, proof не логируется.
5. Target lock → private staged TOML → реальная Rust validation → durable journal
   → atomic replace/fsync → hot apply → health точной runtime revision.
   Поставить реальные validate/reload/health утилиты. Для локального подтверждения
   определить ограниченный IPC/status между агентом и сервером; не считать
   несуществующий gRPC работающим. Отзывать sessions/routes/leases/cache согласованно.
6. Одинаковые revision/content возвращают receipt без повторного reload/backup.
   Та же revision с другим содержимым — conflict; старые revisions не применяются.
   После потери HTTP-ответа проверять durable receipt. После crash согласовать
   journal/disk/runtime до следующего apply. Для идентификатора секретосодержащего
   snapshot использовать keyed digest.
7. UI показывает pending/applied/rolled_back/rollback_failed и desired/applied.
   При недоступном сервере не обещать завершённый отзыв. Подтверждённый отзыв
   защищать durable tombstone/revision barrier: rollback и старый snapshot не
   могут вернуть ключ. Если восстановление нарушает отзыв — fail closed.
8. SQLite и удалённый сервер не образуют общую ACID-транзакцию. Контракт:
   durable desired state, наблюдаемая сходимость и транзакционный apply на агенте.
   Не держать SQLite write transaction во время сетевого запроса.
   Несколько серверов имеют отдельный applied status.

## Обязательные проверки первой цели

- Unit: TOML preservation, schema, PSK, duplicates, ограничения кандидатов,
  tag mismatch, CAS/idempotency, отсутствие секретов в выводе.
- Настоящие panel API + temporary SQLite → mTLS agent → vpn-server → CLI:
  create/apply → authenticated handshake → encrypted packet → revoke →
  новый handshake отклонён, старая сессия не передаёт данные, другая работает.
- Отозванного PSK нет в текущем managed TOML/runtime; проверить delete/disable/expiry.
- Fault injection: validate/reload/health, остановка сервиса, потерянный ответ,
  повторная/переставленная доставка, crash на границах commit; исключить
  восстановление подтверждённо отозванного ключа.
- mTLS: отсутствующий/чужой/просроченный сертификат, неверный hostname,
  недоверенный сервер, redirects, неизвестные targets и лимиты payload.
- Изолированные Linux namespaces/VM с TUN и NET_ADMIN; NET_RAW только для capture.
  Синтетические назначения, уникальный lab project, временные секреты.
  Bidirectional packet evidence и отсутствие трафика отозванной сессии.
- Записать SHA, команды, платформу, capabilities, ограничения и результаты в
  ORBIT-VALIDATION.md до перевода строки матрицы в implemented.

## Порядок следующих веток и границы

Приоритеты 1→6 сохраняются. Каждая цель: небольшие атомарные коммиты
contracts → runtime → tests → RU/EN docs, затем PR с фактическими проверками.
Текущая ветка docs/completion-audit-2.5 содержит только аудит; реализации и PR нет.

| Очередь | Ветка | Условие готовности |
| --- | --- | --- |
| 1 | feat/key-sync-mtls | Описанный create/apply/revoke, live revocation и TUN gates |
| 2 | ci/android-release-signing | Protected release job, repository secrets, verify signer/fingerprint, cleanup, отказ без secrets |
| 3 | test/transport-e2e | TUN e2e TLS/HTTP3/WSS и принимающий ECH frontend; сертификаты, inner hostname, ECH disabled, timeout, обрыв, запрет downgrade |
| 4 | feat/ipv6-datapath | Default deny, opt-in leases/routes и совместимое расширение negotiation; ICMPv6/PMTU, AAAA и leak tests |
| 5 | feat/rtt-ranking-migration | Свежий ACK SRTT, hysteresis/backoff; та же сессия/TUN/IP при смене пути; измеренная TCP continuity |
| 6 | feat/domain-routing | DNS attribution/TTL/CNAME, конфликты, CDN, versioned subscriptions |

APK: debug→release обычно требует reinstall. До удаления приложения пользователь
сохраняет подписки/профили; Android Keystore не переживает uninstall надёжным
для этой задачи образом. Может потребоваться in-app export. Нужны offline backup
постоянного ключа, signing lineage там, где поддерживается, и migration legacy
устройств. Проверить upgrade/reinstall с тестовыми ключами; секреты не логировать.

ECH: ECHConfigList сам по себе не заменяет принимающий HTTP3 frontend.
Rust, Python carrier и Android VpnService фиксировать отдельными строками проверки.

IPv6: одного encrypted carriage мало; нужны обратная маршрутизация, ownership
источников, firewall/forwarding и PMTU. Согласовать routed prefix или NAT66.
Старые клиенты сохраняют формат и default deny.

Failover: межсерверная непрерывность TCP требует того же tunnel IP, egress identity
и состояния routing/conntrack. У независимых серверов этого нет. Сначала заявлять
только проверенную миграцию пути к тому же серверу; межсерверный reconnect может
оборвать TCP. Не вводить непроверенную пересылку session keys ради HA.

Domain routing, предлагаемый порядок: app bypass остаётся исключением Android;
block выше allow, exact выше suffix, более длинный suffix выше короткого,
равноприоритетный конфликт отклоняет обновление. Общий CDN IP не даёт права
bypass для всех его имён; при неоднозначности сохранять tunnel.
DNS provenance/TTL/CNAME/AAAA, cache replacement и существующие flows учитывать
явно. Внешний DoH/DoT не классифицируется надёжно без отдельной политики.
Новые domain rules передавать с явной версией/capability: старый клиент должен
отказаться, а не молча потерять правила.

## Что согласовать до реализации

1. Сохранить 1→6 и первый milestone ограничить полной синхронизацией ключей?
2. Несколько PSK на uid и одновременные устройства: поддерживаем совместимо,
   либо вводим явное ограничение с миграцией? Рекомендую совместимую поддержку.
3. Панель владеет всеми [[users]] или только выделенной managed-областью?
   Какие inbounds соответствуют каждому фиксированному target?
4. Требовать hot reload без разрыва других сессий, немедленный отзыв активной
   сессии и fail-closed при невозможности безопасного recovery? Рекомендую да.
5. Один target сначала или несколько? Рекомендую один с расширяемой схемой.
6. Расширять существующую Docker/TUN lab или отдельные VM? TUN/capabilities
   проверяются в лаборатории; production smoke не допускается.
7. Перед соответствующими следующими целями: владелец APK signing key и Android
   API range; IPv6 prefix; принимающий ECH frontend; DNS/DoH policy; границы HA.
   Эти вопросы не блокируют независимую реализацию первой цели.

Согласование нужно по прямому требованию пользователя «сначала план и согласование».
Навык дополнительного approval не требует. Секреты в чат не присылать.

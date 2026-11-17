# Автоматическая синхронизация credentials (Linux, opt-in)

[English](KEY-SYNC.md)

Панель синхронизирует один настроенный inbound через существующий mTLS-агент.
Без настройки доставка отключена. QR в панели не означает готовность ключа:
дождитесь applied для desired revision. Страница Clients показывает состояние
и номер настроенного inbound; остальные inbounds автоматически не применяются.

## Совместимость и поведение

Handshake, криптографические примитивы, TOML и import URI не изменены.
Под одним uid/tag поддерживается до 16 активных PSK с независимыми сессиями/IP.
Повторное подключение заменяет сессию того же credential. Hot snapshot сохраняет
неизменённые сессии, счётчики и anti-replay, удаляет отозванные сессии, leases,
маршруты и handshake cache согласованно под блокировкой protocol node.

Обычные экземпляры агента сохраняют JSON/TLS API v1. Для TOML используется
отдельный экземпляр того же агента с users_sync: он принимает отдельную операцию
v2 и запрещает generic apply/rollback, чтобы не обойти отзыв. Неизвестные поля
и версии отклоняются. Документ содержит revision, inbound_id, users, identities
отозванных credentials и полный HMAC proof на существующем tag key.
Proof привязан к каноническому документу и revision; несовпадение ключа панели
и сервера обнаруживается до записи. От повторов защищают durable revisions;
отдельного challenge round-trip нет. Ключи, proof и bodies не логируются.

SQLite triggers сохраняют desired revision атомарно с изменениями credentials.
Worker передаёт активные локальные ключи с учётом статуса inbound/пользователя,
expiry и quota; обнаруживает также истечение времени без записи в БД.
Ключи remote subscriptions на свой сервер не отправляются.
Revoke/delete создают durable tombstones; disable/expiry обратимы.
Повтор той же revision после потери ответа не перезапускает сессии.

SQLite и сервер не образуют общую ACID-транзакцию. Pending означает отсутствие
подтверждения datapath; считать такой отзыв завершённым нельзя.

## Настройка

Нужны Python 3.11+, Linux и приватная management-сеть/CA.
Создайте server.toml и закрытый control directory. Запуск сервера:

```sh
vpn-server --config /etc/bproto/server.toml --datapath --control-socket /run/bproto/control.sock
```

Каталог не должен разрешать запись группе/остальным; сокет имеет mode 600.
Для systemd задайте RuntimeDirectory и ExecStart override с этим флагом.
Production systemd в рамках этой проверки не тестировался.

Пример полного agent settings приведён в [English](KEY-SYNC.md#provisioning).
Используется тот же tools/config-agent/agent.py, отдельный экземпляр для TOML:
target=/etc/bproto/server.toml, users_sync.inbound_id=1,
server_binary=/usr/local/bin/vpn-server и control_socket=/run/bproto/control.sock.
Существующий TLS/JSON-экземпляр остаётся на своём target.

Обязательные fixed hooks: health выполняет настоящий probe, stop останавливает
ровно нужный сервис при небезопасном recovery. Пример health — CLI connect по
приватному health-client.toml с отдельным статическим probe credential.
Этот probe проверяет аутентифицированное соединение; при необходимости отдельно
проверяйте datapath. Обычный пользователь для probe не подходит: он может быть
отозван. Команда, просто возвращающая успех, не является deployment-проверкой.

Агенту нужны доступ к control socket, запись config и ограниченное право
выполнить fixed stop hook. Root-агент сохраняет uid/gid существующего файла;
mode остаётся 600. Произвольные команды, target/path из панели запрещены.

В окружении панели задаются:

```text
BPROTO_KEY_SYNC_INBOUND=1
BPROTO_KEY_SYNC_AGENT_URL=https://agent.example.com:9444
BPROTO_CONFIG_AGENT_IDENTITY=/run/secrets/panel-agent-identity.pem
BPROTO_CONFIG_AGENT_CA=/run/secrets/agent-ca.pem
```

Это примеры путей и адреса. Identity PEM содержит клиентский сертификат и ключ.
Разрешён один fixed HTTPS origin, без redirects; доверяется только указанная CA.
Проверяются hostname, срок и назначение сертификата.
Канонический репозиторий: https://github.com/bSECURITY-Team/bProto.

## Владение конфигурацией и восстановление

Управляемые [[users]] добавляются в отмеченную область в конце TOML.
Операторские записи, комментарии и настройки сохраняются. Совпадение uid
статического и управляемого пользователя отклоняется. При миграции ранее
скопированных из панели записей удалите соответствующие статические дубли
в согласованное окно, сохранив приватный backup и отдельный probe credential.
Явный top-level users=[] может потребовать нормализации перед первым запуском:
некорректный candidate отвергается реальным Rust parser.

Порядок применения: Rust validation → private journal → atomic replace/fsync →
local hot reload → keyed runtime receipt → fixed health command.
Hot reload меняет только users; listener/tag_key/donor/TUN/admin требуют restart.

Если неудачно только добавление, восстанавливаются старый файл/runtime и
возвращается rolled_back. Если неудачно удаление, остаётся безопасный candidate,
сохраняется recovery journal, вызывается stop и возвращается rollback_failed.
Удалённый PSK не восстанавливается. Устраните ошибку сервиса/health и запустите
его на candidate; retry завершит journal вперёд. Автоматический start после
fail-closed stop не реализован. После успешного удаления previous backup
также очищается от удалённого PSK.

.users-state, .users-journal и .users-lock хранятся в закрытом каталоге config.
Journal во время recovery содержит секретные старые/candidate bytes.
Нельзя независимо восстанавливать старый state: он несёт revision/tombstones.
Восстановление БД панели и agent state нужно координировать.

Границы: один target и serial worker; несколько panel replicas и атомарность
между серверами не поддерживаются. Payload ограничен 64 KiB и 4096 explicit
tombstones. Превышение видно как отказ доставки; безопасная compaction требует
будущего согласованного epoch-протокола. Старые revocations молча не удаляются.

## Проверки

Команды и результаты — в [ORBIT-VALIDATION](ORBIT-VALIDATION.md).
Loopback e2e использует настоящие panel, mTLS agent, server и CLI.
Отдельная [TUN-лаборатория](../tools/key-sync-lab/README.md) проверяет перенос
пакетов и отзыв живой сессии в разных namespaces с NET_ADMIN, NET_RAW у клиента,
без публикации портов. NAT/Internet, Android и production systemd не проверены.

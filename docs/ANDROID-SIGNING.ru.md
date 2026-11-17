# Release-подпись Android и миграция

[English](ANDROID-SIGNING.md)

Статус: подготовлены signingConfig, CI и проверки артефакта. Четыре теста gate
прошли на subprocess fixtures. Они не доказывают сборку Gradle, наличие настоящего
release APK или обновление установленного приложения. Постоянного keystore
в workspace нет. Hosted CI и реальная подпись пока не проверены; готовую
подписанную поставку не заявляем. Опубликованные APK 2.5.0 остаются историческими
debug-артефактами.

## Настройка репозитория

В GitHub Actions secrets bSECURITY-Team/bProto или разрешённых organization
secrets задайте ANDROID_RELEASE_KEYSTORE_BASE64, ANDROID_RELEASE_STORE_PASSWORD,
ANDROID_RELEASE_KEY_ALIAS и ANDROID_RELEASE_KEY_PASSWORD. В repository variable
ANDROID_RELEASE_CERT_SHA256 задайте независимо проверенный SHA256 сертификата.
Fingerprint публичен, но доверять ему нужно отдельно от проверяемого APK.
Секреты не передаются через чат, issues, Git-файлы или логи.

Постоянный keystore хранится в зашифрованном offline backup с ограниченным
доступом и проверенной процедурой восстановления. Зафиксируйте владельца,
alias и fingerprint. Не генерируйте новый production signer на каждый запуск:
потеря исходного ключа может лишить пользователей возможности обновления.

## Поведение CI

PR выполняет debug-проверки без signing secrets. Trusted version tag получает
проверенные native libraries из того же workflow, создаёт временный keystore
mode 600 в RUNNER_TEMP и выполняет Gradle assembleRelease/testReleaseUnitTest.
apksigner должен подтвердить подпись и ожидаемый единственный signer.
Отсутствие keystore/fingerprint, неверная подпись и другой signer блокируют
публикацию. Release job использует android-release-apk; debug APK не подставляется.
Keystore удаляется также после ошибки и не загружается как artifact.

Для локального release нужны BPROTO_ANDROID_KEYSTORE (путь),
BPROTO_ANDROID_STORE_PASSWORD, BPROTO_ANDROID_KEY_ALIAS и BPROTO_ANDROID_KEY_PASSWORD.
Без них release tasks отклоняются. Пароли передаются через приватное окружение,
без --debug и environment dumps. В CI используется --no-daemon.

## Переход debug → release

Новая release-подпись обычно не обновляет установленное debug-приложение.

1. До удаления приватно сохраните subscription URLs или данные import profiles.
   Если приложение не позволяет получить их, запросите повторную выдачу в панели
   у оператора. Это bearer credentials; не прикладывайте их к тикетам/логам/QR.
2. Убедитесь, что подписку/профиль можно восстановить. Keystore-encrypted store
   не является надёжным backup после uninstall. Универсальный export UI этим
   изменением не добавлен.
3. Сверьте signer APK с опубликованным доверенным fingerprint.
4. Только после проверки восстановления удалите debug app, установите release
   и импортируйте сохранённые подписки/профили.
5. Проверьте соединение/routing; ненужные старые VPN-ключи отзывайте после
   подтверждения успешной миграции.

## Ротация постоянного signer

Предпочтительно сохранять исходный signer. Плановая ротация требует signing
lineage, созданной и проверенной официальным apksigner в контролируемой среде.
Храните старый и новый keystore защищённо. Текущий CI использует одного signer
и не создаёт/применяет lineage автоматически. Простая замена keystore в secrets
не доказывает работоспособное in-place обновление.

API 28+ поддерживает v3 proof-of-rotation с ограничениями конкретного APK,
tooling и устройства. Для поддерживаемых API 26/27 нельзя предполагать принятие
нового signer: сохраняйте совместимую поставку со старым ключом либо используйте
сохранение credentials → reinstall → reimport.
Play App Signing не настроен и имеет отдельную процедуру ротации.

До production-перехода проверьте upgrade установленного старого APK на новых
и старых поддерживаемых устройствах/эмуляторах, нужную lineage и сценарий
переустановки. Заранее опубликуйте границы, fingerprints и recovery-инструкции.
Это ротация подписи APK, не VPN PSK/tag key.

## Открытая приёмка

Нужен запуск hosted tag workflow с настоящими secrets, независимая apksigner
проверка артефакта, package/version/трёх ABI и испытания upgrade/reinstall/reimport
на поддерживаемом Android. Synthetic gate tests эти проверки не заменяют.

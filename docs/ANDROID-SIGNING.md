# Android release signing and migration

[Русская версия](ANDROID-SIGNING.ru.md)

Status: release signing configuration and artifact gates are prepared. Four
negative/contract tests pass for the gate, using subprocess fixtures. They are
not a signed APK, Gradle compilation or an installed-device upgrade test.
No permanent keystore is present in this workspace. Hosted CI and actual release
signing remain unverified; do not mark release distribution ready until those
checks pass. Current published 2.5.0 artifacts remain historical debug artifacts.

## Repository setup

In bSECURITY-Team/bProto, provision these GitHub Actions secrets through the
repository/organization settings, never through an issue, chat or Git-tracked file:

- ANDROID_RELEASE_KEYSTORE_BASE64: base64 encoding of the permanent JKS/PKCS12 store.
- ANDROID_RELEASE_STORE_PASSWORD: store password.
- ANDROID_RELEASE_KEY_ALIAS: signing alias.
- ANDROID_RELEASE_KEY_PASSWORD: private-key password.

Set repository variable ANDROID_RELEASE_CERT_SHA256 to the independently verified
SHA256 fingerprint of the signing certificate. It is public metadata, but it
must be trusted independently from the APK being verified.

Keep an encrypted offline keystore backup with restricted custody and a tested
restore procedure. Record certificate fingerprint, alias, supported API levels
and key ownership. Losing a direct-distribution signing key can prevent updates
to existing installations. Do not generate a new production signer on each run.

## Build behavior

Ordinary PR builds run debug tests and package native libraries without release
secrets. A trusted version-tag run downloads native libraries from the same
workflow, prepares a private mode-600 keystore in RUNNER_TEMP, assembles/tests
the release with Gradle and invokes apksigner verification. It rejects a missing
keystore, missing fingerprint, invalid signature or unexpected/multiple signer.
The release-publishing job consumes android-release-apk, never android-debug-apk.
Cleanup runs even after build/verification failure; no keystore is uploaded.

Gradle refuses release tasks without all four BPROTO_ANDROID signing variables.
For a local trusted build supply BPROTO_ANDROID_KEYSTORE (file path),
BPROTO_ANDROID_STORE_PASSWORD, BPROTO_ANDROID_KEY_ALIAS and
BPROTO_ANDROID_KEY_PASSWORD through a private environment, then run assembleRelease.
Avoid --debug, environment dumps or command arguments containing passwords.
CI uses --no-daemon to avoid a persistent Gradle process holding the environment.

## Migration from debug to release

A new release signer does not normally update an installed debug-signed app.
Do not tell users that changing buildType solves this signature mismatch.

1. Before uninstalling, privately retain each subscription URL or profile import
   credential. Obtain it from the issuing panel/operator if it is not accessible
   in the installed app. These are bearer credentials: no tickets/logs/QR screenshots.
2. Confirm the operator can reissue/import the profile. Do not rely on Android
   backup: the existing Keystore-encrypted profile store may be unreadable after
   uninstall, and a general profile export UI has not been added by this change.
3. Verify the release APK's signer fingerprint against the published trusted value.
4. Uninstall the debug app only after confirming credential recovery, install the
   release APK and reimport the subscriptions/profiles.
5. Test connection and routing on supported Android versions. Revoke unnecessary
   old VPN credentials after the user confirms migration.

## Rotation of a permanent signer

Keep the current signer where possible. For a planned rotation, Android signing
lineage must be generated and verified with the official apksigner tooling in a
controlled signing environment, retaining the old/new keystores securely.
The current CI configuration uses one signer and does not automatically create
or apply a rotation lineage. Do not replace the stored keystore and assume an
in-place upgrade will work.

API 28+ supports v3 proof-of-rotation, subject to the exact APK signing/tooling
and device behavior. API 26/27 in this project's supported range cannot be
assumed to accept a new signer: keep a compatible distribution signed by the
original key or use the backed-up-credentials reinstall procedure.
Play App Signing, if introduced, has its own enrollment/rotation rules and is
not configured or claimed here.

Before changing the production signer, prove upgrades on representative supported
devices/emulators with an installed previous APK, the proposed new APK and the
intended lineage. Also test the legacy reinstall/reimport path. Publish the
compatibility boundary, fingerprints and recovery instructions before rollout.
Signing-key rotation is separate from VPN PSK/tag-key rotation.

## Acceptance still required

Run the hosted trusted-tag workflow with real repository secrets; independently
verify the resulting APK using apksigner; verify package/version/three native ABIs;
perform supported-device upgrade and debug→release reinstall/reimport checks.
A passing synthetic artifact-gate test alone satisfies none of those runtime gates.

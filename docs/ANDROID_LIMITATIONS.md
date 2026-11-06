# Android security boundaries

## Requested capabilities and user consent

The manifest requests `MANAGE_EXTERNAL_STORAGE` for broad shared-storage scanning and `QUERY_ALL_PACKAGES` for installed-app APK inventory. These permissions are sensitive. The app must clearly disclose their purpose, request user authorization through Android, and pass Google Play declaration/review where applicable. A permission being technically requestable does not mean Play has approved its use.

## What the current app can inspect

- Readable files in shared storage that Android exposes after the user grants the relevant access.
- APK archives that are readable from shared storage or exposed through package metadata.
- Package metadata exposed by Android's PackageManager: declared permissions, components, target SDK, and signing-certificate information where available.
- SHA-256 hashes calculated locally, then checked against the currently installed authenticated feed.
- A harmless EICAR test string used only for scanner regression checks.

## What it cannot claim

- It cannot inspect other applications' private data directories or their live process memory.
- It cannot guarantee detection of unknown, modified, obfuscated, packed, runtime-loaded, or polymorphic malware.
- It does not continuously monitor every app, file write, or network connection.
- A hash match is a reputation signal; a no-match is not proof of safety.
- It does not replace Google Play Protect or a professionally validated commercial antivirus engine.
- Scheduled WorkManager refreshes are deferrable and may be delayed by connectivity, battery constraints, or Doze. They update threat intelligence; they do not provide real-time protection.

## Remediation and quarantine

The AES-GCM vault creates and verifies an encrypted app-private copy before attempting source deletion. The UI requires explicit user confirmation. Android or the document provider can reject deletion; the app reports whether the source was actually removed. Listing, restore, and delete APIs are present, but a complete quarantine-management UI and provider-specific restore tests remain outstanding.

This does not silently uninstall applications. An ordinary app cannot remove system apps or bypass Android's package manager confirmation. Deleting a file from flash storage also cannot guarantee physical secure overwrite because of wear levelling and filesystem behavior.

## Network and privacy

The app downloads a public, publisher-signed hash feed over HTTPS. The scanning path does not send file contents or file hashes to the publisher. The publisher workflow queries hash/family metadata from its licensed source and signs the exact feed bytes outside the APK. Provider credentials and the ECDSA private signing key must be stored as GitHub Actions secrets, never in source code or client resources.

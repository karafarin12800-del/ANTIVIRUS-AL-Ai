# ANTIVIRUS AL AI

Privacy-first Android security scanner. This repository starts with a buildable Android MVP foundation and a defensive, explainable scan pipeline.

## Current MVP scope

- User-selected file scanning through Android's Storage Access Framework.
- Streaming SHA-256 calculation with a configurable maximum file size.
- A local, explicit indicator database for known test indicators.
- APK metadata inspection using Android's package parser (no APK execution).
- Permission and component heuristics reported as evidence, never as proof of malware.
- Evidence-based verdicts: known test indicator, suspicious, no known threat, or unsupported/unknown.
- Private app-storage quarantine copy with hash verification. The original file is not silently deleted.
- The current MVP does not uninstall apps or remove original files; those remediation flows are not implemented yet.
- Offline-first operation. No file upload, telemetry, VPN, accessibility service, root, or broad package inventory in this MVP.
- A strict signed-feed verification and storage core is implemented and unit-tested; it is not activated until a production public key and publisher feed are provisioned.

## Important security boundary

A clean result means only that this local MVP found no known indicator in the selected file. It is **not** a guarantee that the file is safe. Permission patterns and APK metadata can create leads for investigation, not definitive malware verdicts. The current local indicator database contains only a benign project test fixture; this is not a production malware-signature database.

The signed-feed core verifies ECDSA P-256 signatures, enforces expiry and monotonic versions, and stores accepted feeds in private app storage. No production signing key, live threat-intelligence source, or malware indicator list is included yet. Feed-signing private keys must never be stored in this repository or the Android application.

## Build

Open the repository in Android Studio or run the CI workflow. The project uses Kotlin, Jetpack Compose, and Android SDK 36. The CI workflow runs unit tests, Android lint, and a debug APK build.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) and the signed-feed design in [docs/THREAT_FEED_FORMAT.md](docs/THREAT_FEED_FORMAT.md).

## Responsible testing

Use benign test files, synthetic indicator data, and the included unit tests. Do not download or execute live malware. The repository does not contain malware samples.

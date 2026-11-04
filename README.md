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
- User-confirmed Android uninstall handoff for an APK package, where applicable.
- Offline-first operation. No file upload, telemetry, VPN, accessibility service, root, or broad package inventory in this MVP.

## Important security boundary

A clean result means only that this local MVP found no known indicator in the selected file. It is **not** a guarantee that the file is safe. Permission patterns and APK metadata can create leads for investigation, not definitive malware verdicts. Real threat-feed coverage, cloud reputation, behavior monitoring, and production malware detection require independently maintained data, backend services, and validation against a lawful benchmark corpus.

## Build

Open the repository in Android Studio or run the CI workflow. The project uses Kotlin, Jetpack Compose, and Android SDK 36. The CI workflow runs unit tests and Android lint.

## Roadmap

1. Harden and validate the local scanner and quarantine flow.
2. Add a signed, versioned threat-intelligence feed with rollback protection.
3. Add an optional hash-reputation backend; never upload file contents without clear consent.
4. Expand APK vulnerability intelligence and evidence-based reports.
5. Conduct independent false-positive, detection, privacy, and performance testing before any public security claims.

## Responsible testing

Use benign test files and the included unit tests. Do not download or execute live malware. The repository does not contain malware samples.

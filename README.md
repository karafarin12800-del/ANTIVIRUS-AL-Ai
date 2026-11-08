# ANTIVIRUS AL AI

## Support

For support requests, bug reports, and product feedback, contact **Zojajiali4@gmail.com**. The Android Settings → Support screen opens the device's email app when available.

Privacy-first Android security scanner. Current Android milestone: **0.3.0 (versionCode 3)**. The app includes a bilingual Persian/English dashboard, automatic quick/deep shared-storage scanning, a bounded local scan pipeline, an authenticated threat-feed client, and an encrypted quarantine vault.

## Implemented security layers

- Bounded device scanning: quick scan up to 350 files/1 GiB; deep scan up to 10,000 files/5 GiB; 200 MiB per file. Results disclose skipped files and incomplete coverage.
- EICAR harmless antivirus test-string detection for scanner regression checks. EICAR is not live malware and is never described as malware.
- APK package metadata inspection without installation or execution.
- Conservative permission/component evidence. Static metadata patterns are leads for review, not proof of malware.
- ECDSA P-256 signed-feed verification with a pinned public key, strict format, expiry, monotonic version checks, and atomic private-storage replacement.
- Hash-reputation verdicts for feed entries classified as MALWARE, PUA, or SUSPICIOUS. These are exact SHA-256 matches, not behavioral or machine-learning detection.
- WorkManager refresh scheduling for the signed feed. Network/battery constraints and Android Doze may delay work; this is not continuous device monitoring.
- AES-GCM private quarantine vault with verified-copy creation, listing, restore, and removal APIs. Source-removal action is restricted to malware/PUA/suspicious verdicts, requires explicit user confirmation and a verified copy, and can still be refused by Android or the document provider. A full quarantine-management screen remains outstanding.
- File contents and file hashes are not uploaded by the scanning path. The app downloads only the public signed feed.

## Live threat-feed activation

The Android client and publisher workflow are prepared, but a live database is **not active until the repository owner configures** these GitHub Actions secrets:

- `MALWAREBAZAAR_AUTH_KEY` — required MalwareBazaar API credential.
- `THREATFOX_AUTH_KEY` — optional ThreatFox API credential; when configured, the publisher includes SHA-256 metadata for malware samples linked to recent ThreatFox IOCs.
- `ALAI_FEED_SIGNING_KEY_PEM` — matching ECDSA P-256 private key; never commit it or place it in the app.
- `ALAI_ABUSECH_COMMERCIAL_USE_APPROVED` — set to `true` only after the owner has confirmed that the selected provider plan and terms allow this commercial use.

The publisher queries hash/family metadata only; it does not download malware samples. MalwareBazaar documents that its community API is free under fair-use principles, while company or for-profit use may require the enhanced commercial API. The approval flag is only an owner attestation; it is not provider approval or legal advice. Do not activate the workflow until the applicable plan/terms have been confirmed.

The private signing key corresponding to the app-pinned public key is a separate secret. If it is lost or compromised, a reviewed app update and key-rotation procedure are required.

## Threat-intelligence source roles

The publisher can combine four metadata sources into the signed v2 feed:

- MalwareBazaar: recent family-labelled SHA-256 file hashes.
- ThreatFox: typed SHA-256, URL, domain, IPv4, and IPv4:port IOCs, plus linked sample hashes when present.
- URLhaus: active/online malware-distribution URLs when its credential and separate commercial-use approval are configured.
- Feodo Tracker: online botnet command-and-control IPv4 indicators.

Entries retain source provenance, confidence, first-seen and expiry timestamps. Duplicate indicators are merged; the feed is capped at 20,000 entries / 4 MiB and marks truncated coverage. No malware sample bytes are downloaded.

Android uses SHA-256 entries for local file reputation. It parses network IOCs separately, but browser, DNS, VPN, socket, and traffic-blocking protection are not yet connected. Network IOCs are therefore not advertised as active network protection. Commercial-use permission must be confirmed for each enabled provider before a commercial feed is published.

## Scanning coverage and current detection limits

- Quick device scan: up to 350 files / 1 GiB.
- Deep device scan and user-selected folder scan: up to 100,000 files / 25 GiB.
- Maximum individual file size: 200 MiB.
- Android-protected private app locations remain inaccessible and excluded.
- The local hash database currently contains only a benign development fixture, not production malware signatures. General content-aware detection for non-APK formats is not implemented.
- As of 2026-11-08, the `security-feed` branch and published `threat-feed/latest.alfeed` do not exist yet. Until a signed feed is published and installed, the app must show threat intelligence as unavailable.

See [Scanning coverage and known limitations](docs/SCANNING_COVERAGE.md) for the exact boundaries and release gates. These limits do not make the app a full or independently validated antivirus product.

## Important Android and detection boundaries

A clean result means only that no currently loaded feed hash or configured static signal matched. It is **not** a guarantee that a file is safe. Hash matching misses unknown, modified, packed, or polymorphic files. The app does not inspect other apps' private data or live process memory, does not replace Google Play Protect, and does not currently provide real-time protection for every app or network connection.

The manifest requests `MANAGE_EXTERNAL_STORAGE` and `QUERY_ALL_PACKAGES` to support broad shared-storage scanning and installed-app inventory. Both are sensitive capabilities and require accurate in-app disclosure and Google Play declaration/review where applicable. Android still restricts other apps' private storage and protected directories such as `Android/data` and `Android/obb`.

Quarantine can remove an accessible source file only when Android/the provider permits deletion. It cannot silently uninstall installed packages, remove system apps, or guarantee physical secure erasure on flash storage.

## Validation status

Automated unit tests cover the signed-feed parser, signature tampering/replay/expiry rejection, EICAR stream matching, and selected static heuristics. Emulator instrumentation covers launch/artwork and AES-GCM quarantine integrity, restore, and deletion; the current API 33/35 run must pass before this revision is treated as validated. No independent AV-TEST/AV-Comparatives-style malware detection report has been completed; no detection-rate or false-positive-rate claim is made.

See `docs/DETECTION_VALIDATION.md`, `docs/THREAT_INTEL_OPERATIONS.md`, and `docs/ANDROID_LIMITATIONS.md`.

## Build

The Android package version is `0.3.0` (`versionCode=3`). GitHub Actions publishes `ANTIVIRUS-AL-AI-v0.3.0-debug.apk` with source commit, workflow run ID, and SHA-256 metadata. Debug APKs are for testing only and are not production-signed release packages. CI runs unit tests, Android lint, APK assembly, and emulator instrumentation tests.

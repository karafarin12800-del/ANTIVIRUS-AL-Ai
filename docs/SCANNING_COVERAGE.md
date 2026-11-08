# Scanning coverage and known limitations

Reviewed: 2026-11-08

## File coverage limits

| Mode | Maximum files | Maximum total data | Per-file maximum |
|---|---:|---:|---:|
| Device quick scan | 350 | 1 GiB | 200 MiB |
| Device deep scan | 100,000 | 25 GiB | 200 MiB |
| User-selected SAF folder | 100,000 | 25 GiB | 200 MiB |

Deep-device and user-selected-folder scans are configured to handle libraries of 60,000 files. They are still bounded: directory depth/visit limits, permission denials, provider errors, the total-byte ceiling, and Android protected locations can make a scan incomplete. Any such condition must be reflected in the report; it must not be described as a complete clean scan.

Android does not expose other apps' private data. In particular, `Android/data` and `Android/obb` are excluded from shared-storage traversal even when the user grants All files access. The app can inspect only files and installed APK components Android makes readable.

The UI keeps at most 60 result details in memory, prioritizes threat findings when selecting those details, and maintains aggregate scanned/threat/unknown/test counts over the full run. The preview is not a complete per-file audit log.

## What the current detection engine actually detects

- Every supported scan path computes a SHA-256 digest.
- A file can be classified as known malware, PUA, or suspicious by an exact SHA-256 match in a successfully authenticated, unexpired signed feed.
- The local indicator database currently contains a benign development fixture only. It is not a production malware-signature database. The native C++ matcher currently contains only a harmless engine self-test rule.
- EICAR recognition is a harmless scanner self-test, not a real malware family.
- APK/ZIP analysis enforces entry-count, per-entry, total-expanded-byte, compression-ratio, and nested-depth limits. It validates DEX headers and records selected sensitive API references; it does not execute bytecode.
- The C++ Aho-Corasick multi-pattern matcher is invoked on the same bounded read pass as SHA-256. It retains rule automaton state, not file contents, and accepts rules only from a validated signed bundle. Until such a bundle is published, the only active built-in pattern is a harmless self-test marker reported as `TEST_MARKER_MATCH`.
- The signed offline content-rule parser, anti-rollback storage, and HTTPS refresh client are implemented. The published bundle is not yet available, so no production content signatures are active. A native-engine no-match is not a clean verdict. ZIP/APK and ELF structure can be inspected, but no-format-match remains incomplete until a production ruleset and coverage benchmark exist.

## Static and behavioral analysis boundary\n\nDEX API references and ELF symbol strings are static capability indicators only. They do not prove that code ran. This app does not execute selected APKs in a dynamic sandbox and cannot instrument other apps’ private processes. True behavioral sandboxing requires a separately isolated emulator service.\n\nML feature extraction is available, but inference remains `NOT_CONFIGURED`; no model score is used in verdicts.\n\n## Threat-feed activation state

The Android client is pinned to:

`https://raw.githubusercontent.com/karafarin12800-del/ANTIVIRUS-AL-Ai/security-feed/threat-feed/latest.alfeed`

As of this review, the repository has no `security-feed` branch, so that URL has no published signed feed. The client must report threat intelligence as unavailable until a valid feed is published and installed. An unavailable feed is never equivalent to a clean verdict.

The feed publisher must not be activated for commercial distribution until the enabled providers' current terms and required paid/commercial permissions have been verified. A configured signing key alone does not populate a malware database.

## Required validation before calling this production-ready

1. Run the automated unit tests, lint, APK build, and emulator instrumentation on the exact commit.
2. On real devices, scan a controlled 60,000-file corpus and verify discovered, scanned, unknown, skipped, and detected totals against an external manifest.
3. Use a lawful, independently curated benchmark with verified benign and malicious hashes/signatures. Report coverage, recall, false negatives, false positives, and performance by file type.
4. Validate fresh-feed update, expiry, invalid signature, offline mode, rollback, and no-feed states.
5. Keep the app's wording aligned with the actual formats and detection layers implemented.

Until the production threat source or an embedded licensed signature engine is active and independently evaluated, the project must be described as an early scanning MVP, not a competitive full antivirus.

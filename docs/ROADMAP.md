# Roadmap

## Phase 0 — Buildable foundation
- Android app shell, file picker, bounded streaming hash.
- APK metadata inspection without execution.
- Explainable heuristic evidence and safe test fixture.
- AES-GCM private quarantine copy.
- CI build, unit tests, and lint.

## Phase 1 — Detection quality
- Versioned signature and YARA-compatible rule format, including provenance and test cases.
- Signed feed verification, expiry, rollback prevention, and offline update support.
- Expanded APK static analysis and dependency/CVE inventory.
- Larger benign-app corpus to tune false positives.

## Phase 2 — Online threat intelligence
- Backend-only secrets and hash-reputation proxy.
- Explicit opt-in, hash-only queries by default.
- Provider attribution, cache expiry, rate limits, and offline fallback.
- No file-content upload without separate, clear user consent.

## Phase 3 — Remediation and monitoring
- Source removal only when Android's document provider authorizes it and after explicit confirmation.
- System uninstall handoff and verified result tracking.
- Additional monitoring only through supported Android APIs and policy-reviewed permissions.

## Phase 4 — Independent validation
- External security review and penetration test.
- AV-TEST or equivalent independent malware-detection evaluation.
- Privacy, battery, performance, accessibility, and localization review.
- Release signing and reproducible supply-chain controls.

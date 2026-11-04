# Roadmap

## Phase 0 — Buildable foundation
- Android app shell, file picker, bounded streaming hash.
- APK metadata inspection without execution.
- Explainable heuristic evidence and safe test fixture.
- AES-GCM private quarantine copy.
- CI build, unit tests, and lint.

## Phase 1 — Detection quality
- [x] Strict versioned threat-feed format and ECDSA P-256 public-key verification core.
- [x] Key-ID keyring interface to support planned public-key rotation.
- [x] Feed expiry, clock-skew, size, entry-count, duplicate-entry, and rollback validation.
- [x] Atomic private-storage feed replacement and persistent version floor.
- [x] Unit tests using generated test-only signing keys and synthetic indicators.
- [ ] Provision a production signing key securely; embed only its public key in the app.
- [ ] Add feed import/update UX and integrate verified indicators into scan verdicts.
- [ ] Publish a signed, maintained indicator feed with provenance and test cases.
- [ ] Expand APK static analysis and dependency/CVE inventory.
- [ ] Build a larger benign-app corpus to tune false positives.

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

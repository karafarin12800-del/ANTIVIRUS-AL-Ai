# Roadmap

## Phase 0 — Buildable Android foundation
- [x] Bilingual Android dashboard and scan centre.
- [x] Automatic quick/deep shared-storage scan paths with progress and access-limit reporting.
- [x] Streaming SHA-256 and bounded per-file scan.
- [x] APK package metadata inspection without loading or executing packages.
- [x] Evidence-based permission heuristics; no “safe” guarantee.
- [x] AES-GCM quarantine vault APIs with integrity-checked restore and explicit source-removal attempt.
- [x] CI unit tests, lint, debug APK assembly, and emulator instrumentation coverage (current launch test still being stabilized).

## Phase 1 — Hash reputation and static detection
- [x] Strict ALAI v1 feed format and ECDSA P-256 signature verification.
- [x] Pinned release public key; private key remains external to source and APK.
- [x] Expiry, clock-skew, size, entry-count, duplicate/sort, and rollback checks.
- [x] Runtime feed lookup is integrated into per-file SHA-256 scan verdicts.
- [x] WorkManager schedules network-constrained feed refresh (best effort, not real-time).
- [x] EICAR safe test marker and stream-boundary regression tests.
- [x] Publisher workflow and hash-only MalwareBazaar recent-detections adapter prepared.
- [ ] Configure provider API credential, the matching signing-key secret, and confirm commercial-use entitlement/terms.
- [ ] Run and verify the first successful feed publication; measure feed age, size, and family coverage.
- [ ] Expand APK static analysis with bounded DEX string signals and false-positive calibration.
- [ ] Add a larger lawful benign-app corpus and benchmark set before making accuracy claims.

## Phase 2 — Production threat intelligence and analysis
- [ ] Add a backend reputation proxy, key rotation, provider-health monitoring, rate limiting, and emergency revocation.
- [ ] Evaluate additional licensed sources and curated YARA/signature engines; preserve source attribution and licensing.
- [ ] Add behavior analysis only through supported, policy-compliant Android facilities and a reviewed design.
- [ ] Do not upload file content by default; any hash lookup or telemetry must be transparent and opt-in.

## Phase 3 — Remediation and monitoring
- [x] Verify encrypted quarantine copy and source hash before requesting removal.
- [x] Expose vault list/restore/delete APIs and accurate source-removal result.
- [ ] Build quarantine-management UI, restore destination flow, and recovery tests on multiple document providers.
- [ ] Add Android uninstall handoff with explicit user confirmation; no silent uninstall.
- [ ] Design any continuous monitoring only through supported Android APIs, with battery, privacy, and Play policy review.

## Phase 4 — Independent validation and release readiness
- [ ] Measure precision, recall, false-positive rate, false-negative rate, unknown coverage, scan latency, and battery cost on a lawful benchmark.
- [ ] Complete an external security review and independent AV detection evaluation (AV-TEST or equivalent).
- [ ] Resolve all critical/high findings and publish a reproducible report.
- [ ] Complete Play Console permission declarations for MANAGE_EXTERNAL_STORAGE and QUERY_ALL_PACKAGES.
- [ ] Complete privacy, retention, accessibility, localization, billing, release-signing, and supply-chain reviews.

# Real Detection Engine: Technical Research and Implementation Plan

Reviewed: 2026-11-08
Audited branch: `feature/multisource-threat-intelligence`
Audited commit: `5109f9cdb127491450cce5e876d91ad631e2295e`

## Executive decision

Do not attempt to turn the current SHA-256 reputation scanner into a full antivirus by increasing file-count limits or by adding more UI. Keep the existing Kotlin scanner as the orchestration, storage-permission, hashing, reporting, and quarantine layer. Add a separately testable content-detection engine behind a narrow interface. The preferred first engine to evaluate is **YARA-X**, subject to an Android NDK/Rust integration spike, ABI/build validation, performance tests, and rule-source licensing review.

YARA-X is a pattern-matching engine, not a complete antivirus by itself. It only detects what its installed rules describe. Production capability therefore depends on a maintained, reviewed, signed, legally redistributable rule set and independent evaluation. Do not advertise YARA-X integration as malware protection until these gates pass.

## Verified repository findings

### Current scanner behavior

- `ScanLimits.kt` configures deep-device and selected-folder scans for 100,000 files and 25 GiB, with a 200 MiB per-file cap. These are traversal/resource ceilings, not detection coverage.
- `ScanEngine.scan()` streams each input into a temporary file while calculating SHA-256, then checks a local indicator, the harmless EICAR self-test marker, the authenticated feed's exact hash map, and APK metadata/permission heuristics.
- There is no general content-signature engine invoked for arbitrary files. For non-APK files without a hash match, the result is `UNSUPPORTED_FILE`.
- APK inspection is metadata/permission analysis; it is not DEX bytecode malware analysis, behavioral analysis, or a general static signature engine.
- `ThreatIntelligenceProvider.kt` contains `OfflineThreatIntelligenceProvider`, which always returns `NotConfigured`.
- `ThreatFeedRuntime.kt` loads only the pinned signed feed URL. The repository's audited tree contains no `security-feed` branch, so no published feed was available at audit time.
- `docs/SCANNING_COVERAGE.md` already documents that the local database is a benign development fixture and that the feed is not active.
- `DeviceScanEngine.kt` and `FolderScanEngine.kt` enforce Android storage/provider boundaries and resource ceilings. Android does not expose arbitrary other-app private data; a scan report must state its actual scope.

### Important verdict-design concern

A non-empty signed hash feed is not proof that all scanned file formats or threat families are covered. The current `threatCoverageComplete` condition (fresh feed, non-null, non-truncated, non-empty indicator map) is only evidence that a feed snapshot exists. It must not be treated as proof of comprehensive detection coverage for every file type. The new design must separate **feed validity**, **format coverage**, and **scan completeness**.

## Proposed layered architecture

### Layer 0 — Safe acquisition and inventory

- Keep Android SAF and explicitly granted shared-storage access. Do not attempt to bypass Android sandbox or protected directories.
- Enumerate candidates with bounded queues and bounded metadata retention.
- Preserve per-file failures, inaccessible roots, provider errors, cancellation, depth/visit limits, and file/byte caps.
- Use streaming reads and a bounded buffer. Avoid retaining file contents or unbounded candidate/result lists in memory.
- A file changed during scanning, unreadable content, unsupported provider behavior, or early stop must be recorded as incomplete.

### Layer 1 — Cryptographic reputation

- Compute SHA-256 during the same read pass used by the content engine where practical.
- Compare against a signed, versioned, expiring local indicator snapshot.
- Keep hash matches as high-confidence reputation evidence, with source, classification, family, confidence, first-seen, expiry, and feed version.
- A hash non-match means only “not present in this exact snapshot”; it is not a clean verdict.
- Do not upload file contents. Any future hash lookup must be explicit, privacy-reviewed, opt-in, and use a documented provider contract.

### Layer 2 — Content signatures (primary next implementation)

- Prototype YARA-X as a Rust library compiled for Android ABIs and called through a small, stable JNI boundary.
- Keep the native interface narrow: initialize a validated compiled rule bundle; scan a read-only file descriptor or bounded stream; return rule identifiers and structured metadata; release resources deterministically.
- Do not pass arbitrary rule source from an untrusted network directly into a compiler in production. Compile and validate rule bundles in a controlled build/release pipeline, sign the bundle, pin accepted signing keys, enforce bundle size/rule-count/complexity limits, and support rollback protection.
- Run rule scans with strict per-file time, memory, and match-count limits. A timeout or engine error is UNKNOWN/INCOMPLETE, never CLEAN.
- Rules must be authored or obtained under explicit redistribution rights. Each rule needs provenance, license, author/source, review status, version, supported formats, confidence, and expiry/review date.
- Begin with a small internally authored test rule pack that only recognizes harmless fixtures. Do not ship copied community rules until each rule's license and redistribution rights are recorded.

### Layer 3 — Format-aware static inspection

Add parsers incrementally, starting with APK/ZIP and DEX metadata, then ELF and selected document formats only where a maintained parser exists and resource limits can be enforced.

- Validate container structure, lengths, offsets, compression ratios, entry counts, nesting depth, and malformed-input behavior.
- Inspect metadata and static indicators without executing, installing, or loading scanned content.
- Treat parser errors and unsupported formats as UNKNOWN/INCOMPLETE.
- Permission patterns are supporting evidence only. A permission or capability alone must not classify an APK as malware.

### Layer 4 — Conservative heuristic scoring

- Combine independent evidence classes (e.g., signed reputation, content rule match, structural anomaly, APK metadata).
- Avoid classifying a file as malware solely from a filename, extension, permission, packer hint, or single weak heuristic.
- Separate confirmed malware, PUA, suspicious, test fixture, unknown, and clean-with-defined-coverage.
- Keep explainable evidence codes and rule IDs for every non-clean result.

### Layer 5 — On-device ML (later, optional)

Do not start with a neural model. First establish a lawful, representative, independently labelled dataset and reliable static features. Any model must run offline, disclose model version, provide calibrated confidence, be tested for drift and false positives, and never override a confirmed signature match. ML-only signals should produce a review/suspicious result, not a confirmed-malware verdict.

## Verdict contract

Introduce a scan coverage object independent of the verdict:

- `enumerationComplete`: all in-scope candidates were enumerated.
- `fileReadComplete`: the individual file was read to EOF without mutation/provider errors.
- `hashReputationAvailable`: a fresh authenticated snapshot was loaded.
- `contentEngineAvailable`: native engine initialized and its signed rule bundle passed validation.
- `formatCoverage`: explicit set of formats actually parsed/scanned.
- `limitsReached`: any file, byte, depth, directory, timeout, memory, or result cap was reached.
- `errors`: structured failures with counts and examples.

Suggested result semantics:

| Verdict | Meaning |
|---|---|
| `KNOWN_MALWARE` | High-confidence signed reputation or reviewed high-confidence content rule match |
| `POTENTIALLY_UNWANTED` | Explicit PUA evidence; not conflated with malware |
| `SUSPICIOUS` | Multiple independent but non-conclusive signals |
| `TEST_MARKER_MATCH` | Harmless test fixture only; never counted as live malware |
| `NO_KNOWN_INDICATOR` | File read completed and relevant configured detection layers ran for a declared supported format; means no match in those layers, not a guarantee of safety |
| `UNKNOWN_APK` | APK-looking file could not be safely parsed |
| `UNSUPPORTED_FILE` | No applicable content/format engine exists for this type |
| `INCOMPLETE_THREAT_INTELLIGENCE` | Required feed/rules unavailable, stale, invalid, or incomplete |
| `SCAN_INCOMPLETE` | Enumeration/read/limit/cancellation/error prevented complete analysis |

A device-level report may say “no detections in the scanned scope” only if enumeration completed and all selected in-scope files were processed. It must still show unsupported/unknown counts and formats. Never convert unknown, skipped, unreadable, truncated, or cancelled work into clean.

## Large-library performance plan (60k–100k files)

- Use a bounded producer/consumer pipeline: one enumerator, a small fixed number of file workers, and a bounded queue. Start with one or two workers on mobile and tune by measured device class.
- Avoid one coroutine/task per file and avoid keeping all candidate objects in RAM.
- Persist resumable scan state in a database using a scan ID, root/tree URI permission, stable document identity where available, last completed item, file size/modified time, and engine/rule/feed versions. Revalidate identity and modification metadata before resuming.
- Support cancellation at directory and read-buffer boundaries; clean temporary files in `finally`.
- Stream hash and engine input from the same source where the native API permits. Do not copy every file to a temporary file unless a parser explicitly requires seekable input; if a temporary file is needed, enforce quota and guaranteed cleanup.
- Record discovered, queued, scanned, matched, suspicious, unknown, skipped, unreadable, and failed totals independently.
- Keep only a bounded findings preview in memory; persist the complete structured result log.
- Apply per-file byte caps, total-byte caps, wall-clock budgets, native memory caps, archive entry limits, decompression limits, and thermal/battery-aware scheduling.
- Distinguish SAF document IDs from filesystem paths. Do not assume every content provider reports accurate file sizes or stable IDs.
- Benchmark on low-memory devices as well as current devices; a 100,000-file configured ceiling is not a performance guarantee.

## Engine selection and licensing

### Preferred spike: YARA-X

The upstream project describes YARA-X as a Rust rewrite for matching textual and binary patterns; the crate is BSD-3-Clause. This is a strong fit for a commercial closed-source Android application from a licensing perspective, provided required notices are included and every rule pack's license is separately cleared. It is not a turnkey Android antivirus and does not provide a universal malware database. Native Android integration, supported Rust toolchain, Android ABI packaging, JNI, performance, and rule-module compatibility must be proven in CI before adoption.

### Do not directly embed ClamAV/libclamav in this closed-source app without legal review

ClamAV documents GPLv2 licensing. Linking the library into a proprietary app raises copyleft obligations and is not the default choice for this product. A separate service/process is not automatically a solution; architecture and distribution obligations need legal review.

### Existing threat feeds

Keep the existing signed-feed envelope and provenance model, but do not enable commercial redistribution until current provider terms and any required commercial plans are verified. Provider IOC feeds are not a replacement for file-content signatures. Network IOCs are not active network blocking unless a separate Android VPN/DNS/network enforcement feature is implemented and tested.

## Test strategy and release gates

1. Unit tests for coverage-state transitions, verdict precedence, timeouts, cancellation, malformed parser inputs, changed-file detection, and feed/rule expiry.
2. Native integration tests for each supported Android ABI and minimum supported API level.
3. Benign corpus: common documents, media, archives, APKs, empty files, large files, malformed-but-benign files, and files with misleading extensions.
4. Harmless EICAR test string only in a controlled test fixture; it must remain labelled as a test marker and must never be counted as live malware.
5. Threat benchmark: lawful, independently curated, licensed test corpus. Do not download or execute live malware as part of ordinary CI. Validate hashes/signatures against trusted benchmark manifests.
6. Measure recall, false-negative rate, false-positive rate, precision, unknown rate, format coverage, scan throughput, peak RSS, battery/thermal cost, and crash rate. Publish dataset provenance and test date.
7. 60,000-file deterministic fixture test: compare discovered/scanned/skipped/error totals against a manifest; include nested directories, duplicate files, unreadable/provider-failure simulations, cancellation, and byte-limit exhaustion.
8. No public “antivirus-grade” or “real-time protection” claim until independent detection evaluation and application security review pass.

## Implementation milestones

### M0 — Correctness and coverage accounting
- Add explicit `SCAN_INCOMPLETE` and structured coverage state.
- Fix any clean verdict that relies only on non-empty feed presence.
- Add tests for stale/missing/truncated feed and unsupported formats.
- Add aggregate counts and resumable scan record design.

### M1 — YARA-X Android feasibility spike
- Build a minimal Rust/JNI library for arm64-v8a and armeabi-v7a (and x86_64 emulator if required).
- Add a harmless internally authored test rule and fixture.
- Verify signed rule-bundle loading, match reporting, timeout behavior, and release packaging.
- Benchmark 1,000-file and 60,000-file synthetic benign corpora before expanding rule coverage.

### M2 — Production rule lifecycle
- Establish rule provenance/licensing inventory, review process, signatures, versioning, expiry, rollback protection, and emergency revocation.
- Add controlled rule update and offline fallback behavior.

### M3 — Format coverage
- Add APK/DEX/ELF and selected document/container parsers incrementally with adversarial malformed-input tests and strict resource budgets.

### M4 — Independent evaluation
- Run a reproducible, lawful benchmark and independent security review. Only then decide whether product positioning and store claims can be upgraded.

## Official technical references

- YARA-X upstream project and BSD-3-Clause license: https://github.com/VirusTotal/yara-x
- YARA-X Rust crate API (Compiler, Rules, Scanner): https://docs.rs/yara-x/latest/yara_x/
- YARA-X crate metadata and license: https://docs.rs/crate/yara-x/latest
- ClamAV documentation and GPLv2 license statement: https://docs.clamav.net/
- Android embedded DEX security documentation (relevant to safe treatment of APK/DEX artifacts): https://developer.android.com/privacy-and-security/security-dex

## Audit conclusion

The present repository is an early scanning MVP with file enumeration, streaming SHA-256, signed-feed parsing, APK metadata heuristics, quarantine, and test fixtures. It is not yet a general content-based antivirus engine. The immediate engineering priority is to make coverage/verdict semantics rigorous, then prove YARA-X Android integration with a harmless test rule, then build a legally cleared and independently evaluated rule lifecycle. Do not claim that the 100,000-file limit means 100,000 files can be reliably classified as malware or clean.

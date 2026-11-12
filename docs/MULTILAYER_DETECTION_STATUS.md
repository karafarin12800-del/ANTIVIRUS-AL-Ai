# Multi-layer detection implementation status

Reviewed: 2026-11-08

## Implemented in this branch

- C++ Aho-Corasick multi-pattern scanner connected through JNI. It scans the same bounded byte stream as SHA-256 and does not retain file contents.
- Rule admission is bounded by 512 total rules, 256 bytes per pattern, 64 KiB total pattern bytes, and a 64 KiB maximum JNI chunk.
- A strict ECDSA P-256 signed offline content-rule bundle format, expiry and monotonic-version validation, atomic installation, and HTTPS refresh client.
- WorkManager attempts the optional signed content-rule refresh alongside the existing signed hash-feed refresh. A missing rule bundle does not invalidate a successfully refreshed hash feed.
- Bounded ZIP/APK structural inspection: entry count, per-entry size, total expanded bytes, compression-ratio checks, safe path-name detection, and nested archive depth.
- DEX header validation and static references to selected sensitive Android/Java APIs.
- ELF header inspection and static symbol-string references. Native libraries are inspected as bytes and never loaded or executed.
- Multi-signal heuristic grouping and deterministic feature extraction for a future on-device model.
- Scan results carry static-analysis coverage, matched rule IDs, rule-bundle version, and explicit ML-model readiness.

## Important scope boundaries

- The C++ engine contains only the harmless built-in self-test rule until a correctly signed production rule bundle is published. The bundle parser/runtime is implemented, but the security-feed content-rules latest.alrules object is not yet published.
- No live malware samples, payloads, or unlicensed signature rules are bundled.
- DEX API references and ELF symbol strings are static indicators of capabilities, not proof that those behaviors occurred.
- No app is dynamically executed in a sandbox by this scanner. Android does not allow this app to freely instrument other apps' private processes. Dynamic behavioral analysis requires a separately isolated emulator/sandbox service and a reviewed data-handling model.
- ML feature extraction is implemented, but model inference is explicitly NOT_CONFIGURED. A model must not be shipped before a licensed, labelled training/validation corpus and independent false-positive/false-negative evaluation exist.
- The existing signed hash feed remains a separate reputation layer. It is not equivalent to a content-signature rule set and network IOCs are not active traffic blocking.

## Required next validation

1. Run C++ host tests, Kotlin unit tests, Android lint, APK assembly, and API 33/35 instrumentation on this exact branch.
2. Add a signed rule bundle generated in the controlled release pipeline only after rule provenance, redistribution rights, and private-key access are verified.
3. Benchmark the 60,000-file corpus, measuring throughput, peak memory, CPU/thermal impact, archive limits, and exact discovered/scanned/skipped counts.
4. Obtain independent labelled benchmark evaluation before publishing detection-rate claims.

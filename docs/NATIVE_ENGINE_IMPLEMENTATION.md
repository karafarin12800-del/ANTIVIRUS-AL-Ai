# Native C++ Detection Engine — implementation status

Reviewed: 2026-11-08

## What is now in the app

- Android builds a native shared library named `libalai_scan_engine.so` with CMake and the Android NDK.
- Kotlin opens one native session for each scanned file and sends the exact bytes already being read for SHA-256 to C++ in bounded chunks. No full file buffer is retained by the native matcher.
- The C++ matcher retains at most the short overlap needed to detect a marker split across two input chunks. Chunk length is capped at 64 KiB; the current Kotlin reader uses a smaller buffer.
- JNI session lifetime is explicit: create, update, finish, destroy.
- The current native rule set is intentionally named `builtin-selftest-only-v1`. It recognizes one harmless internal self-test string only. It does not contain malware signatures and must not be described as detecting malware.
- Native-engine availability/completion, rule-set ID, rule matches, and a machine-readable error code are stored separately on `ScanResult`.

## Coverage correction

A current, non-empty signed SHA-256 feed is not proof that APK/DEX content is covered. A feed non-match no longer promotes an APK to `NO_KNOWN_INDICATOR`; until a reviewed APK/DEX content ruleset is enabled, the result remains `INCOMPLETE_THREAT_INTELLIGENCE` unless independent heuristic evidence warrants `SUSPICIOUS` or a positive reputation match is found.

## Test gates added

- Native host tests cover an in-chunk marker, a marker split across chunks, ordinary text, update-after-finish rejection, oversized-chunk rejection, and the bounded-overlap invariant.
- Android instrumentation tests verify that the packaged JNI library loads and returns the expected result for both a split marker and ordinary text.
- Android CI builds the app's native library for `arm64-v8a`, `armeabi-v7a`, and `x86_64`, and runs the C++ host tests.

## Work still required before malware detection claims

1. Replace the self-test-only rule table with a signed, versioned, reviewed and legally redistributable content rule bundle.
2. Add format-aware APK/ZIP and DEX structural parsing with strict entry-count, nested-depth, decompression, offset, time and memory limits.
3. Connect those structural signals to conservative, explainable multi-signal scoring. A single permission, filename, malformed field, or weak heuristic must not confirm malware.
4. Add independent benign and licensed threat benchmark evaluation, including precision, recall, false-positive/negative rates, throughput, peak memory, thermal cost, and the deterministic 60,000-file accounting test.

No live malware files are included or executed by these tests. EICAR remains a harmless self-test only.

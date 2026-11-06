# Test plan

## Automated unit tests included

- SHA-256 known-answer and lowercase hex checks.
- Local benign project fixture and unknown-hash behavior.
- Harmless EICAR test-string recognition across stream-buffer boundaries.
- EICAR near-miss and ordinary-text rejection; test marker is never counted as live malware.
- Signed-feed parser accepts generated P-256 test signatures and rejects payload tampering, unknown keys, expired feeds, future issue time, duplicate/unsorted hashes, and rollback.
- Permission heuristic calibration: one sensitive permission alone is not malware; exported components remain informational.
- Existing APK archive identification tests for renamed, malformed, and non-APK files.

## CI validation gates

1. `testDebugUnitTest`, `lintDebug`, and `assembleDebug` must all pass.
2. APK ZIP integrity and build metadata must be verified.
3. Instrumentation tests must decode the shipped robot resource and launch the real launcher Activity.
4. An instrumentation failure must be investigated from the test report/logcat; a green assembly step is not evidence that the app launched.
5. Signed threat-feed publisher tests must remain offline/mocked and must not require a live API key in pull requests.

## Required Android device tests before public release

- Verify file selection, automatic quick/deep scans, provider-backed files, empty/small/large files, changed-after-scan handling, and cancellation.
- Test API 26 through current Android versions, including protected storage boundaries, app inventory visibility, split APKs, and malformed archives.
- Validate Android Keystore AES-GCM encryption, tag-tamper detection, key invalidation, vault list/restore/delete, and restore through multiple document providers.
- Confirm source deletion is never attempted before explicit confirmation and a verified encrypted copy; validate the "source not removed" failure state.
- Verify that installed apps are not silently uninstalled and system applications cannot be removed by this vault.
- Verify WorkManager refresh only updates signed threat intelligence; measure actual delay under Doze, low battery, no network, and metered connectivity. Do not market this as real-time monitoring.
- Measure scan latency, memory peak, battery use, thermal behavior, and low-end device stability.
- Review Play declarations, privacy disclosures, permissions, data retention, and consent.

## Detection benchmark and external evaluation

Use a lawful, independently curated dataset in a controlled lab. Report recall, false-negative rate, false-positive rate, precision, F1, coverage, unknown rate, and performance by file type and size. Separate confirmed malware from PUA and benign EICAR. Keep tuning and test sets separated by family/time.

An independent detection report (AV-TEST, AV-Comparatives, or equivalent) and independent application security review are release gates. Do not claim commercial-grade detection until those reports exist.

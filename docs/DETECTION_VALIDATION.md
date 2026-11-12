# Detection validation plan

## Current status

**No independent malware-detection evaluation has been completed.** No detection-rate, recall, precision, or false-positive percentage is claimed. CI success and the EICAR regression test do not establish commercial antivirus quality.

The current detection stack consists of:
- Exact SHA-256 matching against the currently accepted publisher-signed feed (only when a non-expired feed has been published and installed).
- Conservative APK permission/component evidence.
- A harmless EICAR test string used to validate the scanner path.
- Explicit unknown/unsupported results rather than silently declaring unsupported content clean.

Hash matching alone does not detect byte-modified, obfuscated, packed, polymorphic, or previously unseen malware.

## Required benchmark design

Use a lawfully obtained, independently curated, isolated benchmark managed by qualified security testers. Do not use personal devices or normal user data for testing. The dataset must have documented provenance, file hashes, labels, collection dates, family diversity, and licensing/usage rights.

Minimum benchmark composition before any public accuracy claim:
- Confirmed malicious files from multiple families and file types.
- A representative benign corpus, including popular signed Android applications and common document/archive formats.
- Potentially unwanted applications labelled separately from confirmed malware.
- Unknown/unlabelled samples reserved for coverage and abstention analysis.
- The harmless EICAR test file for pipeline validation only; it must not be included in the malware-positive count.

Split data by family and time where possible to avoid leakage from near-duplicates. Keep the test set hidden from rule tuning. A qualified independent lab should control sample handling.

## Metrics to publish

Report the numerator, denominator, confidence interval, and dataset version for every metric:

- True-positive rate / recall.
- False-negative rate.
- False-positive rate on benign files.
- Precision / positive predictive value.
- F1 score, with class imbalance documented.
- Coverage: percent of files receiving a supported verdict.
- Unknown/unsupported and scan-error rates.
- Detection latency and throughput by file size/type.
- Peak memory, battery use, thermal behavior, and cancellation responsiveness.

Never combine PUA with confirmed malware when reporting the primary malware recall or precision. Report hash-match results separately from static heuristic results.

## Regression tests in CI

- Correct EICAR test-string recognition across input-buffer boundaries.
- Near-miss and ordinary text rejection.
- Signed-feed parser accepts valid test signatures and rejects changed payloads, unknown keys, expiry, future issue times, duplicate/unsorted entries, and rollback.
- Unknown hashes remain unmatched.
- A single sensitive permission does not independently classify an APK as malware.
- High-signal combinations produce evidence without being represented as proof.
- APK launch/instrumentation tests remain a separate gate from unit tests and lint.

## Independent evaluation gate

Before marketing this as a commercial antivirus, commission an independent detection evaluation (AV-TEST, AV-Comparatives, or an equivalent qualified laboratory), plus application security review and penetration testing. Publish the exact product version, test date, benchmark methodology, sample counts, exclusions, and full limitations. Do not infer the app's performance from other products' results.

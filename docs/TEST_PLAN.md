# Test plan

## Unit tests included

- SHA-256 known-answer test and lowercase hex formatting.
- Exact recognition of the benign project test fixture.
- Unknown hashes remain unmatched.
- One sensitive permission alone does not cause a suspicious verdict.
- A high-signal permission combination is flagged for review.
- Exported components are informational and do not independently raise the verdict.

## Device tests required before public release

1. Test file selection and streaming with empty, small, large, renamed, and provider-backed files.
2. Verify cancellation, low storage, unreadable URI, and file-changed-after-scan cases.
3. Test APK parsing across API 26 through current Android, including malformed and split-package cases.
4. Verify Android Keystore AES-GCM encryption, tamper detection, key invalidation, and storage cleanup.
5. Verify uninstall handoff against installed, non-installed, system, and device-admin packages.
6. Measure scan latency, memory peak, battery use, and thermal behavior on low- and mid-range devices.
7. Evaluate detection and false positives using a lawful, isolated benchmark dataset managed by qualified testers. Never run live malware on a personal device.
8. Review Play declarations, privacy disclosures, retention, and consent before adding cloud or package-inventory features.

A green unit-test or CI build is not evidence of production-grade malware detection.

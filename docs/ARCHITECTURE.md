# Architecture

## MVP data flow

1. The user selects one file through Android's Storage Access Framework.
2. The app streams it to a temporary private cache file while calculating SHA-256.
3. The local indicator store checks the exact hash. Its only bundled match is a benign project test fixture.
4. If the file is an APK, Android's package parser extracts manifest-level metadata. The APK is not installed or executed.
5. Conservative heuristics evaluate selected permission combinations and a small number of configuration signals.
6. The report displays evidence and distinguishes a heuristic lead from a known indicator.
7. At the user's request, QuarantineManager writes an AES-GCM encrypted copy to internal app-private storage and verifies its plaintext hash.

## Engine boundaries

- File hash engine: streaming SHA-256 and bounded file reading.
- Local indicator database: exact hash matches from the local indicator store.
- APK metadata inspector: package name, target SDK, permissions, exported component count, debug flag, and signer certificate fingerprint.
- Permission risk analyzer: conservative metadata heuristics; it never asserts malware from a permission alone.
- Threat intelligence provider: future hash-only reputation boundary. The current implementation is offline and returns NotConfigured.
- Quarantine manager: encrypted copy with Android Keystore AES-GCM; it does not silently delete the source.
- Remediation boundary: the current MVP does not uninstall apps or remove the original selected file; quarantine stores an encrypted copy only.

## Signed feed trust boundary

- `SignedThreatFeedParser` authenticates the exact feed payload with ECDSA P-256 / SHA-256 before accepting indicator data.
- `EcdsaP256KeyringVerifier` accepts only pinned public keys identified by a key ID; it supports overlapping keys for planned rotation.
- `SignedThreatFeedStore` stores feeds in a caller-supplied private directory, atomically replaces feed content, and maintains a persistent monotonic version floor.
- Freshness, future clock skew, validity duration, input size, indicator count, hash format, sorting, duplicate detection, and rollback are checked.
- This component is not yet connected to a production key, publisher, import UI, or scan verdict pipeline. Test keys are generated at runtime and synthetic test indicators are never treated as real malware.

## Production requirements not implemented

A production release needs a securely provisioned publisher key, maintained signed threat-feed data with provenance, a feed update UX, scan-pipeline integration, backend hash reputation, APK library/CVE inventory, false-positive handling, independent detection validation, and a dedicated security review.

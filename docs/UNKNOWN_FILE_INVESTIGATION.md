# Unknown file investigation

## Current behavior

When a scan ends as `UNKNOWN_APK`, `UNSUPPORTED_FILE`, or
`INCOMPLETE_THREAT_INTELLIGENCE`, the app creates a local investigation case.
The case is keyed by the validated SHA-256 digest and stores only bounded
analysis metadata and evidence codes. It deliberately excludes the original
filename, filesystem path, and file bytes.

The local queue is bounded to 100 records and de-duplicates by SHA-256.
A missing or malformed hash is rejected. A no-match, unavailable service, or
unconfigured source is never converted into a benign verdict.

## Online reputation lookup

The current build does **not** query an external reputation provider. The case
records `remote_lookup_state=NOT_CONFIGURED`. A production provider requires
a maintained HTTPS backend, provider terms/licensing review, server-side API
credentials, request timeouts, rate limits, cache TTLs, source attribution,
and conflict handling. Provider secrets must not be embedded in the APK.

The first remote request should contain only the SHA-256 digest. Full-file
submission is not implemented and must never occur automatically. Do not
execute unknown files on the device. Any future sandboxing belongs in an
isolated server-side environment with explicit authorization and privacy
controls.

## Verdict policy

- Unknown is not malicious and is not benign.
- A remote timeout or empty response remains unknown.
- Conflicting provider claims must be surfaced as a conflict for review.
- A remote claim alone must not become a permanent trusted signature or
  training label; curated review and signed feed publication are required.

## Validation

Unit tests cover verdict eligibility, hash validation, metadata minimization,
and the invariant that confirmed verdicts are not queued as unknown.
Android CI runs unit tests, lint, API 33/35 instrumentation, APK signature
verification, and unsigned AAB preflight. The CI APK is debug-signed and is
not a Play Store release artifact. Store signing requires the release
keystore to be provisioned through protected CI secrets.

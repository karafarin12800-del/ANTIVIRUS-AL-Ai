# Signed threat-feed format (ALAI v1)

## Security model

The Android client accepts only feeds signed by a pinned ECDSA P-256 public key. The app contains public keys only; feed-signing private keys must remain in a controlled publisher environment and must never be committed to Git or packaged in the APK.

The parser authenticates the exact UTF-8 bytes before interpreting indicator entries. It rejects malformed UTF-8, CRLF, missing final newline, unknown key IDs, invalid signatures, duplicate or unsorted hashes, expired feeds, feeds issued too far in the future, excessive validity windows, oversized feeds, and version rollback.

The current implementation is a verified parser and private-storage component. It is **not yet connected to a production publisher, a production public key, a feed-import screen, or the scan verdict pipeline**. No real malware indicators are bundled by this change. The only entries used by tests are synthetic fixtures.

## Canonical file layout

The file is UTF-8, uses LF line endings, and ends with a newline:

```text
ALAI-THREAT-FEED/1
key_id=release-2026
version=42
issued_at=1799999940
expires_at=1800086400
entry=<64 lowercase hex SHA-256>|FAMILY.ID|MALWARE
entry=<64 lowercase hex SHA-256>|FAMILY.ID|PUA
signature=<Base64 DER-encoded ECDSA signature>
```

Entries are sorted by SHA-256 in ascending lexicographic order. Hashes are unique. The signature is ECDSA P-256 with SHA-256 over every byte from the format header through the newline after the last entry. The final `signature=` line is excluded from the signed payload.

Allowed classifications are `MALWARE`, `PUA`, and `SUSPICIOUS`. Family identifiers use uppercase letters, digits, periods, underscores, and hyphens. The feed is limited to 2 MiB, 20,000 indicators, and a maximum 30-day validity period. A publisher should issue a new monotonically increasing version for every update.

## Key rotation

The verifier accepts a keyring keyed by `key_id`, allowing a release to include both the current and next public key during a planned rotation. Publish a feed with the new key ID only after the app version containing that public key is available. Retire the old key only after the migration window has passed.

## Storage and rollback controls

The store writes the highest accepted version to app-private storage before replacing the current feed. This ordering is deliberate: a crash can temporarily make the previous feed unavailable, but it cannot make an older feed acceptable. The feed file is replaced through a temporary file and an atomic move when supported.

The version floor is stored in ordinary app-private storage, not backed by hardware monotonic storage. It protects against accidental replay and normal app-level replacement; it is not a claim of resistance to a rooted or fully compromised device.

## Before production activation

1. Generate a production P-256 signing key in a controlled environment or hardware-backed key service.
2. Keep the private key outside the repository and outside the Android app.
3. Embed only its X.509 public key in a reviewed app release and define a key ID.
4. Build a feed publisher that canonicalizes entries, signs the exact payload bytes, and maintains a monotonic version.
5. Add signed-feed import/update UX, freshness status, key-rotation procedure, revocation handling, and scan-engine integration.
6. Validate against a lawful, independently curated benchmark and measure false positives before making detection claims.

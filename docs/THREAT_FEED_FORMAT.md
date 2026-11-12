# Signed threat-feed format (ALAI v1 and v2)

## Security model

The Android client accepts feeds signed by the app-pinned ECDSA P-256 public key. The APK contains public-key material only; the matching private signing key stays in a protected publisher environment and must never be committed or packaged.

The parser verifies the exact UTF-8 payload bytes before interpreting entries. It rejects malformed UTF-8, CRLF, missing final newline, unknown key IDs, invalid signatures, duplicate or unsorted indicators, invalid typed values, expired feeds, future issue times, excessive validity windows, oversized feeds, and version rollback.

The reader remains backward-compatible with legacy v1 SHA-256 feeds. The publisher now emits v2 typed indicators. Android stores SHA-256 indicators for local file reputation and parses network indicators as separate metadata. Parsing a URL, domain, IPv4 address, or IP:port does **not** mean the app currently filters browser traffic, DNS, sockets, or VPN traffic.

## Canonical v1 layout

```text
ALAI-THREAT-FEED/1
key_id=alai-release-2026
version=42
issued_at=1799999940
expires_at=1800086400
entry=<64 lowercase hex SHA-256>|FAMILY.ID|MALWARE
signature=<Base64 DER-encoded ECDSA signature>
```

V1 entries are sorted by SHA-256 and unique. Allowed classifications are `MALWARE`, `PUA`, and `SUSPICIOUS`.

## Canonical v2 layout

```text
ALAI-THREAT-FEED/2
key_id=alai-release-2026
version=42
issued_at=1799999940
expires_at=1800604740
source_count=FEODO_TRACKER|1
source_count=MALWAREBAZAAR|1
source_count=THREATFOX|1
source_count=URLHAUS|1
feed_truncated=0
entry=DOMAIN|<base64url-value>|THREATFOX.FAMILY|SUSPICIOUS|THREATFOX|80|1799999900|1800086340
signature=<Base64 DER-encoded ECDSA signature>
```

V2 entry fields are:

1. Indicator type: `SHA256`, `URL`, `DOMAIN`, `IPV4`, or `IP_PORT`.
2. Indicator value encoded as canonical, unpadded Base64URL UTF-8.
3. Source-prefixed family identifier.
4. Classification: `MALWARE`, `PUA`, or `SUSPICIOUS`.
5. Sorted, unique comma-separated provenance sources.
6. Confidence score from 0 through 100.
7. First-seen Unix timestamp.
8. Per-indicator expiry Unix timestamp.

Source-count metadata records how many retained indicators each source contributed. The parser independently recomputes those counts and rejects mismatches. `feed_truncated=1` means source/type caps excluded additional otherwise valid indicators; a non-match is not exhaustive.

The publisher caps the total at 20,000 indicators and 4 MiB, with per-type limits: 16,000 SHA-256, 2,000 URLs, 1,000 domains, 500 IPv4 addresses, and 500 IPv4:port values. The feed expires after seven days. URLhaus and Feodo Tracker entries use a shorter one-day per-indicator lifetime in the current publisher.

The signature is ECDSA P-256 with SHA-256 over every UTF-8 byte from the format header through the newline after the last entry. The final `signature=` line is excluded from the signed payload. Files use LF line endings and end with a newline.

## Key rotation and rollback

The verifier uses a keyring keyed by `key_id`. A reviewed app release may include both the current and next public key during a planned rotation. Publish under a new key ID only after an app version containing that public key is available. Retire the old key only after the migration window.

The highest accepted version is persisted before the current feed is replaced. A crash may temporarily make the old feed unavailable, but must not make an older version acceptable. The version floor is app-private storage, not hardware monotonic storage; it is not a claim of resistance to a rooted or fully compromised device.

## Production activation gate

1. Confirm each provider's current terms and commercial entitlement for the intended use and redistribution.
2. Configure only the necessary API credentials and commercial-use approvals as protected GitHub Actions secrets.
3. Keep the private signing key outside source control, logs, artifacts, and the Android package.
4. Run the key-only check first; it must not contact providers or publish a feed.
5. Generate a candidate feed only after approvals are verified.
6. Validate the signed candidate with the Android parser and test freshness, rollback, truncation, and source provenance.
7. Verify the live feed URL and the app's accepted-feed status before describing the intelligence database as active.
8. Do not make detection-rate or product-safety claims without an independently curated benchmark and independent evaluation.

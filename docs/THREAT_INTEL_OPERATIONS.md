# Threat intelligence operations

## Sources and current ingestion behavior

The publisher builds a bounded metadata-only feed from four sources:

- **MalwareBazaar**: authenticated `recent_detections` query over the previous 168 hours. Imports family-labelled SHA-256 file indicators as `MALWARE` with confidence 100.
- **ThreatFox** (optional credential): authenticated `get_iocs` query over the previous seven days. Imports supported IOC types (`sha256_hash`, `url`, `domain`, `ip`, `ipv4`, and `ip:port`) and linked malware-sample SHA-256 metadata. Non-hash IOCs are classified `SUSPICIOUS`; sample/file hashes are classified `MALWARE`. Provider confidence is retained with a bounded 0–100 value.
- **URLhaus** (optional credential and separate approval): imports only active/online distribution URLs from its recent file export. These URL indicators receive a one-day per-indicator expiry. A URL reputation indicator is not proof that every later response from that URL is malicious.
- **Feodo Tracker** (enabled by publisher configuration): imports only online IPv4 command-and-control indicators from its recommended blocklist, with a one-day per-indicator expiry and `SUSPICIOUS` classification.

No malware samples or payload bytes are downloaded, executed, or bundled. Only threat metadata is queried. Duplicate indicators are merged by type and normalized value, provenance sources are retained, and the highest classification/confidence is preserved according to publisher rules.

## What Android currently uses

Android applies exact SHA-256 reputation matches to local file scans. It verifies the signed feed, key ID, expiry, indicator ordering, provenance counts, truncation marker, and monotonic version before accepting it.

The client also parses URL, domain, IPv4, and IP:port indicators into a separate network-metadata collection. The current app does **not** yet connect those network indicators to a VPN, DNS resolver, browser protection, socket monitor, or traffic-blocking path. Do not describe those indicators as active network protection until such a separately reviewed feature exists and is tested.

A fresh-feed non-match is not proof that a file is safe. An expired, unavailable, invalid, or truncated feed must not produce a green clean verdict.

## Bounds and expiry

- Total maximum: 20,000 retained indicators.
- Feed maximum: 4 MiB.
- Per-type limits: 16,000 SHA-256, 2,000 URLs, 1,000 domains, 500 IPv4, 500 IPv4:port.
- Feed validity: seven days.
- Current URLhaus and Feodo Tracker per-indicator validity: one day.
- Every v2 entry includes type, normalized value, family identifier, classification, provenance, confidence, first-seen time, and expiry.
- The signed header records source counts and whether any configured per-type/total cap truncated the candidate.

A truncated feed is useful intelligence but has incomplete coverage. The app must expose that state and abstain from a definitive no-match result.

## Commercial-use and provider credentials

Availability of an API endpoint does not itself grant permission for commercial use, caching, redistribution, or inclusion in a paid antivirus product. The repository owner must independently confirm the current terms and required plan/authorization for **each** source before activating it in a commercial release. The workflow approval variables are operator attestations only; they are not provider approval or legal advice.

MalwareBazaar/ThreatFox and URLhaus have separate approval gates in the publisher. Feodo Tracker terms must also be checked before commercial redistribution. Keep a source disabled if the required permission is uncertain.

## GitHub Actions secrets

| Secret | Purpose |
|---|---|
| `MALWAREBAZAAR_AUTH_KEY` | Required MalwareBazaar API credential |
| `THREATFOX_AUTH_KEY` | Optional ThreatFox API credential |
| `URLHAUS_AUTH_KEY` | Optional URLhaus export credential |
| `ALAI_FEED_SIGNING_KEY_PEM` | ECDSA P-256 private signing key matching the Android-pinned public key |
| `ALAI_ABUSECH_COMMERCIAL_USE_APPROVED` | Operator attestation only after MalwareBazaar/ThreatFox terms are confirmed |
| `ALAI_URLHAUS_COMMERCIAL_USE_APPROVED` | Separate operator attestation only after URLhaus terms are confirmed |
| `ALAI_ENABLE_FEODO_TRACKER` | Enables/disables Feodo Tracker ingestion; do not enable for commercial redistribution until terms are confirmed |

Never put a private signing key or provider credential in source code, the APK, an issue, a log, or a chat message.

## Publisher workflow

`.github/workflows/publish-threat-feed.yml` supports a manual key-only check and a separate publish operation, and it is scheduled every 12 hours once available on the default branch.

The key-only operation verifies the configured private key matches the public key pinned in Android. It must not contact any provider, generate a feed, or publish a file.

The publish operation:
1. Fails closed when required credentials or approvals are missing.
2. Queries only configured provider metadata endpoints.
3. Normalizes and validates each indicator type.
4. Deduplicates by type/value and preserves provenance.
5. Applies per-type and total caps and reports truncation/source coverage.
6. Creates a monotonically increasing version with seven-day feed expiry and shorter URLhaus/Feodo indicator expiries.
7. Signs exact canonical UTF-8 bytes using ECDSA P-256 / SHA-256.
8. Publishes only the signed feed and version marker to the `security-feed` branch.

The live feed is not active until a successful approved publish exists and the Android client has downloaded and accepted it.

## Incident response and key rotation

If a signing key is compromised, stop publishing, rotate under controlled conditions, release an app update containing the new public key, and follow the keyring migration procedure in `THREAT_FEED_FORMAT.md`. Never publish with a key that released clients do not trust. Record each key change and feed-version transition.

## Operational release checklist

- Provider terms and commercial entitlement confirmed separately for every source enabled.
- Required Actions secrets configured and protected.
- Key-only workflow succeeds without contacting providers.
- Publish workflow succeeds and creates a non-empty signed candidate.
- Feed URL returns HTTP 200 and the Android client accepts the signature.
- Source counts, truncation state, feed expiry, per-indicator expiry, and monotonic version are sensible.
- A known hash match is reported as a reputation match; an unknown hash remains a no-match only when coverage is current and not truncated.
- A stale/unavailable/truncated feed never appears as a clean scan.
- No file contents or scanned file hashes are uploaded by the Android scanning path.
- Network indicators are not advertised as active protection until a separate network enforcement feature is implemented and validated.

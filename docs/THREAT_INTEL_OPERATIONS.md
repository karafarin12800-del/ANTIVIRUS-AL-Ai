# Threat intelligence operations

## Data source and scope

The publisher uses two complementary abuse.ch sources through authenticated HTTPS metadata APIs:

- **MalwareBazaar**: `recent_detections` returns files for which the source assigned a malware-family label. Their SHA-256 values and family labels are imported as exact-file indicators.
- **ThreatFox (optional)**: `get_iocs` over the last seven days returns recent IOCs. When its API credential is configured, the publisher imports SHA-256 values only from each IOC's documented `malware_samples` metadata and retains the associated family label.

No malware sample bytes are retrieved or executed. The Android scanner compares a local SHA-256 value with the signed hash list. A match is a reputation signal for the exact byte-identical file; a modified or previously unseen sample can evade hash matching. MalwareBazaar's family label takes precedence when the same hash appears in both sources.

The feed currently contains only entries for which the source returned a family label. Missing or malformed hashes and missing family labels are discarded. Duplicate hashes are collapsed, entries are sorted, and the feed is capped at 20,000 indicators / 2 MiB.

## Commercial-use and provider credentials

MalwareBazaar states that its community API is free under fair-use principles, while companies or for-profit use may require a paid enhanced commercial API. Before activating this publisher for a commercial antivirus product, the repository owner must confirm the applicable plan and terms with the provider. The workflow's boolean commercial-use secret is an operator attestation only; it does not grant provider permission.

## GitHub Actions secrets

Configure these secrets in the repository settings after reviewing the current provider terms:

| Secret | Purpose |
|---|---|
| \`MALWAREBAZAAR_AUTH_KEY\` | Required API Auth-Key for MalwareBazaar metadata queries |
| \`THREATFOX_AUTH_KEY\` | Optional ThreatFox API Auth-Key; when configured, a failed query stops feed publication |
| \`ALAI_FEED_SIGNING_KEY_PEM\` | Unencrypted PEM for the matching ECDSA P-256 private key |
| \`ALAI_ABUSECH_COMMERCIAL_USE_APPROVED\` | Literal \`true\` only after commercial-use entitlement/terms are confirmed |

Never put the private key or API key in a workflow file, commit, APK, log, or issue. The matching public key is pinned in the Android application as key ID \`alai-release-2026\`.

## Publisher workflow

\`.github/workflows/publish-threat-feed.yml\` can be started manually and is scheduled every 12 hours after the workflow is available on the default branch. It:

1. Fails closed if any credential or the explicit commercial-use attestation is missing.
2. Queries up to 168 hours of recent family-labelled MalwareBazaar detections.
3. When \\`THREATFOX_AUTH_KEY\\` is configured, queries up to seven days of recent ThreatFox IOCs and imports only their associated sample SHA-256 metadata.
4. Canonicalizes, sorts, and deduplicates SHA-256 entries.
5. Generates a monotonic version and a seven-day expiry.
6. Signs the exact UTF-8 payload with ECDSA P-256 / SHA-256.
7. Publishes only \\`threat-feed/latest.alfeed\\` and its version marker to the \\`security-feed\\` branch.

The Android app downloads this public file over HTTPS. It rejects an unknown key ID, invalid signature, malformed/unsorted/duplicate entries, expired/future feeds, oversized input, excessive validity windows, and rollback.

## Incident handling and key rotation

If a signing key is compromised, stop the publisher workflow, rotate the key in a controlled environment, release an app update containing the new public key, and follow the keyring migration procedure in \`THREAT_FEED_FORMAT.md\`. Do not publish a feed under a key the released app does not trust. Record every key change and feed-version transition.

## Operational checks

Before calling the feed live, confirm all of the following:

- Provider terms and commercial entitlement are confirmed by the repository owner.
- All required Actions secrets are configured and protected.
- A manual workflow run succeeds and publishes a non-empty feed.
- The feed URL returns HTTP 200 and the Android client accepts the signature.
- The accepted feed has a current expiry and increasing version.
- A known hash in the feed is reported as a known malware match, while an unknown hash remains unmatched.
- No file content or scanned hash is sent to the provider by the Android client.

## URL and network indicators

URLhaus is a separate source for malicious distribution URLs, host/domain indicators, and collected payload hashes. Its documentation warns that a collected payload hash is not automatically malicious because a URL may later serve clean content. The current Android scanner is a local file-hash/APK scanner and does not inspect browser navigation or all device network connections, so URLhaus URL/domain indicators are not mixed into the file-malware hash feed or advertised as active protection. A future URL-reputation component must evaluate URLs/hosts in an actual browsing or network workflow and implement freshness/revocation handling.

For commercial or for-profit deployment, confirm the applicable abuse.ch enhanced commercial API terms for each selected source before setting the operator approval secret. Community API availability does not itself authorize commercial use.
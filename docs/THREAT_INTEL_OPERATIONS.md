# Threat intelligence operations

## Data source and scope

The publisher queries MalwareBazaar \`recent_detections\` using its authenticated HTTPS API. It requests only recent metadata and emits:

- SHA-256 file hashes.
- Malware family labels supplied by the source.
- The fixed \`MALWARE\` classification.

It does not retrieve or execute malware samples. The Android scanner compares a local SHA-256 value with the signed hash list. A match is a strong reputation signal for the exact byte-identical file; a modified or previously unseen sample can evade hash matching.

The feed currently contains only entries for which the source returned a family label. Missing or malformed hashes and missing family labels are discarded. Duplicate hashes are collapsed, entries are sorted, and the feed is capped at 20,000 indicators / 2 MiB.

## Commercial-use and provider credentials

MalwareBazaar states that its community API is free under fair-use principles, while companies or for-profit use may require a paid enhanced commercial API. Before activating this publisher for a commercial antivirus product, the repository owner must confirm the applicable plan and terms with the provider. The workflow's boolean commercial-use secret is an operator attestation only; it does not grant provider permission.

## GitHub Actions secrets

Configure these secrets in the repository settings after reviewing the current provider terms:

| Secret | Purpose |
|---|---|
| \`MALWAREBAZAAR_AUTH_KEY\` | API Auth-Key for feed metadata queries |
| \`ALAI_FEED_SIGNING_KEY_PEM\` | Unencrypted PEM for the matching ECDSA P-256 private key |
| \`ALAI_ABUSECH_COMMERCIAL_USE_APPROVED\` | Literal \`true\` only after commercial-use entitlement/terms are confirmed |

Never put the private key or API key in a workflow file, commit, APK, log, or issue. The matching public key is pinned in the Android application as key ID \`alai-release-2026\`.

## Publisher workflow

\`.github/workflows/publish-threat-feed.yml\` can be started manually and is scheduled every 12 hours after the workflow is available on the default branch. It:

1. Fails closed if any credential or the explicit commercial-use attestation is missing.
2. Queries up to 72 hours of recent family-labelled detections.
3. Canonicalizes, sorts, and deduplicates SHA-256 entries.
4. Generates a monotonic version and a seven-day expiry.
5. Signs the exact UTF-8 payload with ECDSA P-256 / SHA-256.
6. Publishes only \`threat-feed/latest.alfeed\` and its version marker to the \`security-feed\` branch.

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

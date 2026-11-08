# Signed content-rule bundle format

## Purpose

The Android client accepts only a bounded, ECDSA P-256 signed bundle authenticated by the app-pinned public key. Rules are compiled into the native C++ multi-pattern matcher and scanned locally. The app never downloads or executes malware samples.

## Bundle format

UTF-8, LF line endings, final newline required:

```
ALAI-CONTENT-RULES/1
key_id=alai-release-2026
version=UNIX_VERSION
issued_at=UNIX_SECONDS
expires_at=UNIX_SECONDS
rule=RULE_ID|FAMILY_ID|CLASSIFICATION|CONFIDENCE|SOURCE_ID|LICENSE_ID|PATTERN_BASE64URL|DESCRIPTION_BASE64URL
signature=BASE64_ECDSA_DER
```

The signature covers every byte from the format header through the final rule line, including each LF newline. The signature line is not part of the signed payload.

- Classification: `MALWARE`, `PUA`, or `SUSPICIOUS`.
- Rule IDs must be sorted, unique, and match `[A-Za-z0-9._-]{1,64}`.
- Family IDs must be uppercase stable identifiers.
- Pattern bytes: 4–256 bytes each; maximum 511 rules and 64 KiB total pattern bytes.
- Every rule includes a stable source ID and SPDX-style license ID; both are retained in the scan evidence for provenance review.\n- Description: UTF-8, 1–240 characters.
- Bundle: maximum 1 MiB and maximum 14-day validity.
- Version must strictly increase; expired, invalidly signed, malformed, oversized, or rolled-back bundles are rejected.
- Accepted bundles are written atomically to app-private storage. Only the public verification key is embedded in Android.

## Publisher input

`tools/publish_content_rules.py` accepts a reviewed CSV with exactly these columns:

`id,family,classification,confidence,source_id,license_id,pattern_base64url,description`

The publisher requires the GitHub secret `ALAI_FEED_SIGNING_KEY_PEM` and two explicit release attestations:

- `ALAI_CONTENT_RULES_REVIEWED=true`
- `ALAI_CONTENT_RULES_COMMERCIAL_USE_APPROVED=true`

The publisher verifies that the private key corresponds to the public key pinned in Android. The private key must never be committed, included in the APK, or pasted into chat.

These approval flags are owner attestations, not legal advice or provider authorization. Every rule needs documented provenance, redistribution rights, review, and a defensible classification before it is included.

## Current activation state

The parser, verifier, atomic store, HTTPS client, WorkManager refresh path, and publisher are implemented. No production bundle is published yet. Therefore the only active native rule is the harmless internal self-test marker; no production malware content signatures are currently active.

# Signed content-rule bundle format

## Purpose

The Android client accepts only a bounded, ECDSA P-256 signed bundle authenticated by the app-pinned public key. Rules are compiled into the native C++ multi-pattern matcher and scanned locally. The native engine finds individual byte patterns; Kotlin applies each source rule's match-group threshold before any content-rule verdict is produced.

## Bundle format (version 2)

UTF-8, LF line endings, final newline required:

```
ALAI-CONTENT-RULES/2
key_id=alai-release-2026
version=UNIX_VERSION
issued_at=UNIX_SECONDS
expires_at=UNIX_SECONDS
rule=RULE_ID|FAMILY_ID|GROUP_ID|MIN_GROUP_MATCHES|CLASSIFICATION|CONFIDENCE|SOURCE_ID|LICENSE_ID|PATTERN_BASE64URL|DESCRIPTION_BASE64URL
signature=BASE64_ECDSA_DER
```

The signature covers every byte from the format header through the final rule line, including each LF newline. The signature line is not part of the signed payload.

- Classification: `MALWARE`, `PUA`, or `SUSPICIOUS`.
- Rule IDs must be sorted, unique, and match `[A-Za-z0-9._-]{1,64}`.
- Family and group IDs are uppercase stable identifiers.
- Pattern bytes: 4–256 bytes each; maximum 511 production rules. Production patterns plus the built-in self-test marker must fit within 64 KiB total.
- Rules in one group must agree on family, threshold, classification, confidence, source, and licence. The number of rules in each group must be at least `MIN_GROUP_MATCHES`.
- The app only surfaces a group as a content-rule match once the required number of distinct pattern IDs match. Partial groups are informational only.
- Every rule includes a stable source ID and SPDX-style license ID; both are retained in the scan evidence for provenance review.
- Description: UTF-8, 1–240 characters.
- Bundle: maximum 1 MiB and maximum 14-day validity.
- Version must strictly increase; expired, invalidly signed, malformed, oversized, or rolled-back bundles are rejected.
- Accepted bundles are written atomically to app-private storage. Only the public verification key is embedded in Android.

## Publisher input

`tools/publish_content_rules.py` accepts a reviewed CSV with exactly these columns:

`id,family,group_id,min_group_matches,classification,confidence,source_id,license_id,pattern_base64url,description`

The publisher requires the GitHub secret `ALAI_FEED_SIGNING_KEY_PEM` and two explicit release attestations:

- `ALAI_CONTENT_RULES_REVIEWED=true`
- `ALAI_CONTENT_RULES_COMMERCIAL_USE_APPROVED=true`

The publisher verifies that the private key corresponds to the public key pinned in Android. The private key must never be committed, included in the APK, or pasted into chat.

These approval flags are owner attestations, not legal advice or provider authorization. Every rule needs documented provenance, redistribution rights, review, and a defensible classification before it is included.

## Initial Android rule source

The initial reviewed rule set contains one grouped Android-malware detection rule:

- Source rule: `WITHSECURELABS_Fallspy` by WithSecure.
- Source repository: `https://github.com/WithSecureLabs/iocs`
- Pinned source commit: `1a8384468dd292c6d2c5114c32e42dc0da1f5ae1`
- Original source file/lines: `GREYVIBE/greyvibe.yara#L121-L139`
- Source rule identifier: `8d0823be-3a64-5e2d-995c-0b2fccf77a98`
- Licence: BSD 2-Clause; copyright `Copyright (c) 2022, WithSecure Oyj`.
- Rule logic: at least 4 of 10 literal strings must match.
- Conservative adaptation: this engine currently uses byte-substring matching and does not enforce YARA's `fullword` modifier. Accordingly, the adapted group is classified `SUSPICIOUS`, not confirmed `MALWARE`; its source score 75 is stored as an ordinal confidence indicator, not as a calibrated probability. A future full YARA-compatible engine should replace this adaptation to preserve all source semantics.

The BSD 2-Clause notice is reproduced in `THIRD_PARTY_NOTICES.md`. The CSV stores only the 10 short string indicators and provenance metadata, not malware samples or payloads.

## Current activation state

The grouped parser, verifier, atomic store, HTTPS client, WorkManager refresh path, and publisher are implemented. The reviewed FallSpy rule source is included in the implementation branch, but it is not active on devices until a signed bundle is published to the `security-feed` branch and downloaded by the app. Publishing requires the matching private-key secret and the two owner approval secrets.

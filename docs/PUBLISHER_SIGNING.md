# Publisher signing and release verification

## CI signing model

Pull-request CI deliberately builds a debug-signed APK and an unsigned release
AAB preflight. Neither artifact is a Play Store release.

The manual workflow
`.github/workflows/publisher-release-signing.yml` signs a release AAB only
on `main`, through the protected GitHub Actions environment
`publisher-release`. The job requires all five environment-scoped secrets:

- `ANDROID_RELEASE_KEYSTORE_BASE64`: base64-encoded Android upload/release keystore
- `ANDROID_RELEASE_KEYSTORE_PASSWORD`: keystore password
- `ANDROID_RELEASE_KEY_ALIAS`: signing key alias
- `ANDROID_RELEASE_KEY_PASSWORD`: private-key password
- `ANDROID_RELEASE_CERT_SHA256`: expected SHA-256 fingerprint of the publisher
  certificate, with or without colon separators

**Required repository configuration:** create a GitHub Actions environment named
`publisher-release`; restrict its deployment branches to `main`; require
approval from a trusted reviewer; and add the five values above as environment
secrets, not repository-wide secrets. Remove any duplicate repository-level
copies after migrating them. The code repository cannot configure or verify
these environment protections.

## Threat-feed publisher environment

Both `.github/workflows/publish-threat-feed.yml` and
`.github/workflows/publish-content-rules.yml` are restricted to `main` and
use a separate GitHub Actions environment named `threat-feed-publisher`.

Create that environment, restrict its deployment branches to `main`, and move
the following values into its environment-scoped secrets:

- `ALAI_FEED_SIGNING_KEY_PEM`
- `MALWAREBAZAAR_AUTH_KEY`
- `THREATFOX_AUTH_KEY`
- `URLHAUS_AUTH_KEY`
- `ALAI_URLHAUS_COMMERCIAL_USE_APPROVED`
- `ALAI_ABUSECH_COMMERCIAL_USE_APPROVED`
- `ALAI_CONTENT_RULES_REVIEWED`
- `ALAI_CONTENT_RULES_COMMERCIAL_USE_APPROVED`

Remove duplicate repository-level copies after migration. Do not put private
publisher keys into source control, APK assets, issues, pull requests, or chat.
Environment-scoped secrets ensure a pull request or non-main workflow cannot
read signing material merely by modifying a workflow file on a branch.

## Verification gates

The release-signing workflow:

1. refuses to proceed if any required secret is missing;
2. decodes the keystore only into the ephemeral runner's temporary directory
   and sets restrictive file permissions;
3. builds the release AAB using Gradle signing configuration sourced from
   environment variables;
4. verifies the JAR signature and validates the AAB archive;
5. extracts the signer certificate SHA-256 and compares it to the separately
   pinned `ANDROID_RELEASE_CERT_SHA256`;
6. uploads the AAB only after the certificate pin matches; and
7. removes the temporary keystore file even when a later step fails.

Passwords and keystore bytes are never written to repository files or build
artifacts. Back up the keystore securely: losing the upload key can complicate
future app updates. If Play App Signing is enabled, distinguish the upload
certificate from the Google-managed app-signing certificate.

## Current provisioning status

The workflows now enforce branch-level guards and reference protected GitHub
Actions environments. This code change does **not** create those environments,
set their branch policies, configure required reviewers, or move existing
secrets. Until the repository owner completes those settings and a real
workflow run passes the certificate fingerprint check, no AAB should be
described as publisher-signed or Play-uploadable.

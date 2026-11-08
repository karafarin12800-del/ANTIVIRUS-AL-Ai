# Publisher signing and release verification

## CI signing model

Pull-request CI deliberately builds a debug-signed APK and an unsigned release
AAB preflight. Neither artifact is a Play Store release.

The manual workflow
`.github/workflows/publisher-release-signing.yml` signs a release AAB only
when all protected repository Actions secrets are present:

- `ANDROID_RELEASE_KEYSTORE_BASE64`: base64-encoded Android upload/release keystore
- `ANDROID_RELEASE_KEYSTORE_PASSWORD`: keystore password
- `ANDROID_RELEASE_KEY_ALIAS`: signing key alias
- `ANDROID_RELEASE_KEY_PASSWORD`: private-key password
- `ANDROID_RELEASE_CERT_SHA256`: expected SHA-256 fingerprint of the publisher
  certificate, with or without colon separators

Configure these secrets in the repository's Settings → Secrets and variables
→ Actions. Prefer an environment-scoped secret set with required reviewers
and restrict release workflow dispatch permissions to trusted maintainers.

## Verification gates

The workflow:

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
artifacts. Do not paste signing credentials into issues, pull requests, chat,
or source code. Back up the keystore securely: losing the upload key can
complicate future app updates. If Play App Signing is enabled, distinguish
the upload certificate from the Google-managed app-signing certificate.

## Current provisioning status

This repository integration does not have permission to inspect or create
GitHub Actions secrets. Therefore the presence and correctness of these five
secrets cannot be confirmed from code review alone. The manual signing
workflow will fail closed with a clear missing-secret error until they are
configured. A successful workflow run and matching certificate fingerprint
are required before describing an AAB as publisher-signed or Play-uploadable.

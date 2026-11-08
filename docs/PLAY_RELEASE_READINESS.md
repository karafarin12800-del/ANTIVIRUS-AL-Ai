# Google Play release-readiness checklist

Last reviewed: 2026-11-08

This document tracks release gates for ANTIVIRUS AL AI. A successful debug APK build is not a Play-ready release.

## Current technical baseline

- Android application ID: `com.antivirusalai`.
- Current development version: `0.3.0`, version code `3`.
- Compile SDK / target SDK: Android 16 / API 36.
- Minimum SDK: API 26.
- CI now builds an unsigned release AAB preflight artifact after the APK, quality, and API 33/35 emulator jobs pass. It validates bundle structure only and is not uploadable to Google Play.
- No production signing keystore or signed release AAB is configured in this repository.

## Required before a public Play submission

### 1. Security and product validation

- [ ] Complete Android unit tests, lint, APK assembly, and API 33/35/36 emulator smoke tests for the exact release commit.
- [ ] Validate threat-feed parsing, signatures, freshness, expiry, rollback, source provenance, and truncated-feed behavior.
- [ ] Keep provider publishing disabled until each provider's commercial terms and required authorization are confirmed.
- [ ] Complete independent malware-detection evaluation and application security review before making performance or detection-rate claims.
- [ ] Test cancellation, low storage, large files, permission denial, Doze, network loss, and damaged quarantine entries.
- [ ] Confirm that all visible feature descriptions match implemented functionality. Network IOC parsing is not active VPN/DNS/browser protection.

### 2. Google Play permissions and disclosures

The current manifest requests `MANAGE_EXTERNAL_STORAGE` and `QUERY_ALL_PACKAGES`. Both access sensitive user/device information and require a careful Play policy review.

- [ ] Confirm that broad shared-storage access is essential to the app's core antivirus function and that Storage Access Framework / MediaStore alternatives are insufficient.
- [ ] Submit the required All files access declaration and provide a clear in-app explanation before requesting the special access.
- [ ] Submit the package-visibility declaration and explain why broad installed-app inventory is core to the antivirus feature.
- [ ] Keep installed-app inventory local and never use it for advertising or analytics monetization.
- [ ] Review foreground-service special-use declarations and ensure the service is user-initiated, transparent, stoppable, and accurately described.
- [ ] Verify that denied permissions leave a useful limited mode and are never repeatedly or coercively requested.

### 3. Privacy and store listing

- [ ] Publish a public privacy-policy page and link it both in the app and in Play Console.
- [ ] Complete an accurate Data safety form based on actual app behavior and all included SDKs/libraries.
- [ ] Prepare store title, short/full descriptions, screenshots, app icon, feature graphic, support contact, and content rating.
- [ ] Describe scan coverage and limitations honestly; do not claim full real-time protection or guaranteed malware removal.
- [ ] Provide a support channel: `Zojajiali4@gmail.com`.

### 4. Release artifact and account

- [ ] Complete the unsigned AAB preflight and inspect its package/version/permissions for the exact release commit.
- [ ] Create a production-signed Android App Bundle (AAB), not a debug APK or unsigned preflight artifact.
- [ ] Use a production signing key controlled by the authorized account owner. Never commit it or send it in chat.
- [ ] Configure protected CI secrets for signing only after the key is securely backed up.
- [ ] Increment versionCode and set the intended release version.
- [ ] Verify the signed AAB, package ID, version, permissions, and SHA-256.
- [ ] Upload to internal testing first, install from Play, and complete a device test before expanding rollout.
- [ ] Complete Play Console declarations and review any policy warnings before requesting production review.

## Target API requirement

As of this review, Google Play requires new apps and updates to target Android 16 (API 36) or higher from 31 August 2026. The current target API is 36, so the target-SDK floor is met; this does not waive permission declarations or other review requirements.

## Official references

- Target API requirements: https://support.google.com/googleplay/android-developer/answer/11926878
- Sensitive permissions and declarations: https://support.google.com/googleplay/android-developer/answer/16558241
- Data safety form: https://support.google.com/googleplay/android-developer/answer/10787469

## Release decision

Do not mark the app production-ready or submit a public release until all required gates above are verified for the exact release commit. Internal debug artifacts may be shared only as test builds and must be labelled accordingly.

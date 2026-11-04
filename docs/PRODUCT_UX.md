# Product UX — Android MVP 0.1.0

## Navigation

The app uses a persistent five-section bottom navigation:

- Home: actual scanner readiness, last scan summary, and shortcuts.
- Scan: the two currently usable scan entry points plus clearly disabled full-device scanning.
- Tools: module catalogue with explicit availability labels.
- Store: plan catalogue for FREE, PLUS monthly/yearly, PRO FAMILY, and LIFETIME OFFLINE.
- Settings: language, privacy, app information, security boundaries, and support-channel status.

The interface supports Persian and English and applies right-to-left layout for Persian.

## Scan modes

### Quick file scan
The user selects one file using Android's Storage Access Framework. The current engine calculates SHA-256 and checks the local indicator fixture. Unsupported formats are reported as unsupported/unknown, not clean.

### APK analysis
The user selects an APK. Android's package parser reads metadata only; the app is not installed or executed. The report can include requested permissions, target SDK, signer certificate fingerprint, and exported components.

### Full-device scan
Visible in the catalogue as unavailable in this MVP. It must not be represented as implemented because ordinary Android apps cannot freely inspect other apps' private data.

## Security tools catalogue

- Encrypted quarantine: stores a verified AES-GCM encrypted copy in private storage. The source file remains unchanged. A full quarantine browser, restore, and deletion flow are not yet implemented.
- APK vulnerability intelligence: planned; no CVE findings are claimed yet.
- Scam and phishing shield: planned; no background message or link monitoring occurs.
- Network guard: planned and subject to Android and store policy review.
- AL AI security brain: evidence aggregation is planned; the current scan result uses the implemented small rule set.
- Self-defense: baseline manifest/build controls exist; runtime anti-tamper monitoring is not claimed.

## Store and monetization

The catalogue shows FREE, PLUS MONTHLY, PLUS ANNUAL, PRO FAMILY, and LIFETIME OFFLINE. It does not show invented prices or fake discounts. Plan details distinguish current FREE features from future premium ideas. Every selection opens an explicit notice that Google Play Billing and subscription management are not integrated and no charge or activation occurs.

Essential safety and reporting features are intended to remain available in the free tier. Actual purchase implementation requires Google Play Billing, regional pricing, purchase acknowledgement, entitlement verification, restoration, subscription lifecycle handling, and server-side validation where appropriate.

## UX and privacy requirements

- Never display a made-up security score, threat count, last-scan time, subscription state, or real-time protection status.
- Label capabilities as available, baseline, planned, or unavailable.
- No file-content uploads in this MVP.
- Never call encrypted-copy storage a deletion or active containment operation.
- Keep unknown and unsupported results distinct from clean results.
- All scanning begins with explicit user file selection.
- No checkout action may claim success before a real store purchase is confirmed.

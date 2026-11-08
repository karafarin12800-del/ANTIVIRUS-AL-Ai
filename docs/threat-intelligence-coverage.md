# Threat-intelligence coverage and safe operation

This is a bounded, metadata-only feed, not a complete global malware database.
It does not replace the local file scanner or behavior analysis.

## Integrated providers

- MalwareBazaar: SHA-256 and family metadata from recent detections (7-day query).
- ThreatFox: SHA-256, URL, domain, IPv4, IPv4:port IOC types from recent IOCs;
  sample-linked SHA-256 metadata only; sample content is never downloaded.
- URLhaus: optional recent URL database export; active/online URL indicators only.
- Feodo Tracker: recommended JSON C2 IPv4 list; online entries only. The
  aggressive historical list is not used to limit false positives.

The publisher merges by (type,value), preserves provider provenance, keeps
the highest confidence, earliest first-seen and latest expiry from confirming
sources. Per-type caps are SHA256 16,000; URL 2,000; DOMAIN 1,000; IPV4 500;
IP_PORT 500. The signed feed records counts per source and a truncation flag.

## Signed format and client behavior

ALAI-THREAT-FEED/2 signs canonical UTF-8 bytes using ECDSA P-256/SHA-256.
Values are Base64URL encoded; every entry includes type, family, classification,
source set, confidence, first-seen and per-indicator expiry. Source counts are
validated against parsed provenance. Android continues to read the old /1
hash-only format and keeps monotonic version checks and atomic replacement.
The maximum feed size is 4 MiB; the maximum number of indicators is 20,000.

The Android parser stores URL/domain/IP indicators as intelligence metadata.
The current scanner still performs SHA-256 file-hash lookup only. This change
does not add VPN, DNS filtering, packet inspection, browser interception or
network blocking. The app must not claim network traffic is monitored.

## Commercial-use gates

MalwareBazaar and ThreatFox publishing still requires the operator-controlled
ALAI_ABUSECH_COMMERCIAL_USE_APPROVED=true secret, after commercial API
entitlement/terms have been verified.

URLhaus is optional and additionally requires URLHAUS_AUTH_KEY and
ALAI_URLHAUS_COMMERCIAL_USE_APPROVED=true. Configuring the key without the
separate approval fails closed. A key-check-only run never contacts providers.

Feodo Tracker's recommended list can be empty after successful takedowns; an
empty dataset does not by itself indicate request failure. ALAI_ENABLE_FEODO_TRACKER
can disable this optional adapter. No secret or private signing key is stored
in source files.

No provider payload, malware binary, sample or executable is downloaded.

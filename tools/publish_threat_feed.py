#!/usr/bin/env python3
"""Build a hash-only, publisher-signed MalwareBazaar feed.

No malware samples are downloaded. The script refuses to run until both
credentials are supplied and an operator explicitly attests that commercial
use is permitted under the selected abuse.ch plan/terms.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


PUBLIC_KEY_B64 = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAzDOX+WcMzHRxjHa/"
    "zC4ZHIUePAR3IxTWtedJPzrM/sov5xWIWbvlnw/WBJczc6Jix9ccV5Z2EqgfKfLaQrNhg=="
)
KEY_ID = "alai-release-2026"
API_URL = "https://mb-api.abuse.ch/api/v1/"
FEED_HEADER = "ALAI-THREAT-FEED/1"
MAX_ENTRIES = 20_000
VALIDITY_SECONDS = 7 * 24 * 60 * 60


def fail(message: str) -> "NoReturn":
    print("ERROR: " + message, file=sys.stderr)
    raise SystemExit(2)


def previous_version(path: str | None) -> int:
    if not path:
        return 0
    try:
        raw = Path(path).read_text(encoding="ascii").strip()
        return int(raw) if raw else 0
    except FileNotFoundError:
        return 0
    except Exception as exc:
        fail("Could not read previous feed version: " + str(exc))


def fetch_recent_detections(auth_key: str) -> list[dict]:
    body = urllib.parse.urlencode({"query": "recent_detections", "hours": "168"}).encode()
    request = urllib.request.Request(
        API_URL,
        data=body,
        headers={
            "Auth-Key": auth_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": "ANTIVIRUS-AL-AI-threat-feed-publisher/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
    except Exception as exc:
        fail("MalwareBazaar API request failed: " + str(exc))

    if len(raw) > 4 * 1024 * 1024:
        fail("MalwareBazaar response exceeded the 4 MiB safety limit.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        fail("Malformed JSON from MalwareBazaar: " + str(exc))

    if payload.get("query_status") != "ok":
        fail("MalwareBazaar did not return query_status=ok: " + str(payload.get("query_status")))
    data = payload.get("data")
    if not isinstance(data, list) or not data:
        fail("No family-labelled recent detections were returned; refusing to publish an empty feed.")
    return data


def clean_family(raw: str, source: str) -> str:
    value = re.sub(r"[^A-Z0-9._-]+", "_", raw.upper()).strip("._-")
    value = value[:60] or "UNCLASSIFIED"
    return source + "." + value


def fetch_threatfox_recent_samples(auth_key: str) -> list[dict]:
    """Return metadata for hashes attached to recent, active ThreatFox IOCs."""
    body = json.dumps({"query": "get_iocs", "days": 7}).encode("utf-8")
    request = urllib.request.Request(
        "https://threatfox-api.abuse.ch/api/v1/",
        data=body,
        headers={
            "Auth-Key": auth_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ANTIVIRUS-AL-AI-threat-feed-publisher/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
    except Exception as exc:
        fail("ThreatFox API request failed: " + str(exc))

    if len(raw) > 4 * 1024 * 1024:
        fail("ThreatFox response exceeded the 4 MiB safety limit.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        fail("Malformed JSON from ThreatFox: " + str(exc))

    if payload.get("query_status") != "ok":
        fail("ThreatFox did not return query_status=ok: " + str(payload.get("query_status")))
    data = payload.get("data")
    if not isinstance(data, list) or not data:
        fail("ThreatFox returned no recent IOC metadata.")
    return data


def make_entries(
    data: list[dict],
    threatfox_data: list[dict] | None = None,
) -> list[tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        sha = str(item.get("sha256_hash", "")).lower()
        signature = str(item.get("signature", "")).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", sha) or not signature:
            continue
        entries[sha] = (sha, clean_family(signature, "MALWAREBAZAAR"), "MALWARE")

    # ThreatFox supplies malware_samples attached to recent IOCs. Import only
    # their SHA-256 metadata and family label; never retrieve sample content.
    for ioc in threatfox_data or []:
        if not isinstance(ioc, dict):
            continue
        raw_family = str(ioc.get("malware") or ioc.get("malware_printable") or "").strip()
        if not raw_family:
            continue
        samples = ioc.get("malware_samples")
        if not isinstance(samples, list):
            continue
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            sha = str(sample.get("sha256_hash", "")).lower()
            if not re.fullmatch(r"[0-9a-f]{64}", sha):
                continue
            # Prefer MalwareBazaar's family label when the same hash occurs
            # in both feeds.
            entries.setdefault(
                sha,
                (sha, clean_family(raw_family, "THREATFOX"), "MALWARE"),
            )

    if not entries:
        fail("The threat sources returned no valid SHA-256 malware indicators.")
    return [entries[key] for key in sorted(entries)[:MAX_ENTRIES]]


def load_private_key(raw_pem: str):
    try:
        key = serialization.load_pem_private_key(raw_pem.encode("utf-8"), password=None)
    except Exception as exc:
        fail("ALAI_FEED_SIGNING_KEY_PEM is not a valid unencrypted PEM private key: " + str(exc))
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        fail("Feed signing key must be an ECDSA P-256 private key.")
    derived = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if base64.b64encode(derived).decode("ascii") != PUBLIC_KEY_B64:
        fail("Private key does not match the public key pinned in the Android app.")
    return key


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--check-key-only",
        action="store_true",
        help="Validate that the configured signing private key matches the app-pinned public key; do not contact providers or publish a feed.",
    )
    parser.add_argument("--previous-version")
    args = parser.parse_args()

    auth_key = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "").strip()
    threatfox_auth_key = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
    private_pem = os.environ.get("ALAI_FEED_SIGNING_KEY_PEM", "")
    commercial_ok = os.environ.get("ALAI_ABUSECH_COMMERCIAL_USE_APPROVED", "").strip().lower()

    if not private_pem:
        fail("Missing ALAI_FEED_SIGNING_KEY_PEM GitHub Actions secret.")
    key = load_private_key(private_pem)
    if args.check_key_only:
        print("Signing-key check: MATCH. The configured private key corresponds to the public key pinned in Android.")
        print("No provider API was contacted and no threat feed was generated or published.")
        return

    if not auth_key:
        fail("Missing MALWAREBAZAAR_AUTH_KEY GitHub Actions secret.")
    if commercial_ok != "true":
        fail("Set ALAI_ABUSECH_COMMERCIAL_USE_APPROVED=true only after confirming the current commercial-use terms.")

    malwarebazaar_data = fetch_recent_detections(auth_key)
    threatfox_data = fetch_threatfox_recent_samples(threatfox_auth_key) if threatfox_auth_key else []
    entries = make_entries(malwarebazaar_data, threatfox_data)
    now = int(time.time())
    version = max(now, previous_version(args.previous_version) + 1)

    signed_payload = FEED_HEADER + "\n"
    signed_payload += "key_id=" + KEY_ID + "\n"
    signed_payload += "version=" + str(version) + "\n"
    signed_payload += "issued_at=" + str(now) + "\n"
    signed_payload += "expires_at=" + str(now + VALIDITY_SECONDS) + "\n"
    for sha, family, classification in entries:
        signed_payload += "entry=" + sha + "|" + family + "|" + classification + "\n"

    payload_bytes = signed_payload.encode("utf-8")
    signature = key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    final_bytes = payload_bytes + (
        "signature=" + base64.b64encode(signature).decode("ascii") + "\n"
    ).encode("ascii")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(final_bytes)
    print("Published-feed candidate: version=" + str(version) + " indicators=" + str(len(entries)))
    sources = "MalwareBazaar recent_detections"
    if threatfox_auth_key:
        sources += " + ThreatFox recent IOC-linked malware_samples"
    print("Sources: " + sources + "; SHA-256/family metadata only; no samples downloaded.")


if __name__ == "__main__":
    main()

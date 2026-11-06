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
    body = urllib.parse.urlencode({"query": "recent_detections", "hours": "72"}).encode()
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


def clean_family(raw: str) -> str:
    value = re.sub(r"[^A-Z0-9._-]+", "_", raw.upper()).strip("._-")
    value = value[:60] or "UNCLASSIFIED"
    return "MALWAREBAZAAR." + value


def make_entries(data: list[dict]) -> list[tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        sha = str(item.get("sha256_hash", "")).lower()
        signature = str(item.get("signature", "")).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", sha) or not signature:
            continue
        entries[sha] = (sha, clean_family(signature), "MALWARE")
    if not entries:
        fail("The API response had no valid SHA-256 hashes with family labels.")
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
    parser.add_argument("--previous-version")
    args = parser.parse_args()

    auth_key = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "").strip()
    private_pem = os.environ.get("ALAI_FEED_SIGNING_KEY_PEM", "")
    commercial_ok = os.environ.get("ALAI_ABUSECH_COMMERCIAL_USE_APPROVED", "").strip().lower()

    if not auth_key:
        fail("Missing MALWAREBAZAAR_AUTH_KEY GitHub Actions secret.")
    if not private_pem:
        fail("Missing ALAI_FEED_SIGNING_KEY_PEM GitHub Actions secret.")
    if commercial_ok != "true":
        fail("Set ALAI_ABUSECH_COMMERCIAL_USE_APPROVED=true only after confirming the current commercial-use terms.")
    key = load_private_key(private_pem)

    entries = make_entries(fetch_recent_detections(auth_key))
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
    print("Source: MalwareBazaar recent_detections; hashes/family labels only; no samples downloaded.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Build a bounded ECDSA-signed offline content-rule bundle from reviewed metadata rules."""
from __future__ import annotations

import argparse
import base64
import csv
import os
import re
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PUBLIC_KEY_B64 = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM1szM5WLCBP0KDTXsrVfBdPxErB4sVo4mhY+duhjfDP5MwASTx0pLor3mSL7dLRwX/gZpi6odLquz/BfIGSafg=="
)
KEY_ID = "alai-release-2026"
HEADER = "ALAI-CONTENT-RULES/1"
MAX_RULES = 511
MAX_PATTERN = 256
MAX_TOTAL_PATTERN = 64 * 1024
MAX_BYTES = 1024 * 1024
VALIDITY = 7 * 24 * 60 * 60
ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
FAMILY_RE = re.compile(r"[A-Z0-9][A-Z0-9._-]{0,79}")
CLASSIFICATIONS = {"MALWARE", "PUA", "SUSPICIOUS"}


def fail(message: str) -> "NoReturn":
    print("ERROR: " + message, file=sys.stderr)
    raise SystemExit(2)


def encode_url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def load_private_key(raw: str):
    try:
        key = serialization.load_pem_private_key(raw.encode(), password=None)
    except Exception as exc:
        fail("ALAI_FEED_SIGNING_KEY_PEM is invalid: " + str(exc))
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        fail("Signing key must be ECDSA P-256.")
    derived = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if base64.b64encode(derived).decode("ascii") != PUBLIC_KEY_B64:
        fail("Private key does not match the public key pinned in the Android app.")
    return key


def read_rules(path: Path) -> list[dict]:
    rules: list[dict] = []
    total_pattern = 0
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            required = {"id", "family", "classification", "confidence", "source_id", "license_id", "pattern_base64url", "description"}
            if set(reader.fieldnames or []) != required:
                fail("CSV must contain exactly: " + ", ".join(sorted(required)))
            for row in reader:
                rule_id = (row.get("id") or "").strip()
                family = (row.get("family") or "").strip()
                classification = (row.get("classification") or "").strip().upper()
                confidence_raw = (row.get("confidence") or "").strip()
                source_id = (row.get("source_id") or "").strip()
                license_id = (row.get("license_id") or "").strip()
                encoded = (row.get("pattern_base64url") or "").strip()
                description = (row.get("description") or "").strip()
                if (not ID_RE.fullmatch(rule_id) or rule_id == "ALAI-NATIVE-ENGINE-SELFTEST"
                        or not FAMILY_RE.fullmatch(family)):
                    fail("Invalid or reserved rule ID/family: " + rule_id)
                if classification not in CLASSIFICATIONS:
                    fail("Invalid classification for rule: " + rule_id)
                try:
                    confidence = int(confidence_raw)
                    pattern = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
                except Exception:
                    fail("Invalid confidence or Base64URL pattern for rule: " + rule_id)
                if not 1 <= confidence <= 100 or not 4 <= len(pattern) <= MAX_PATTERN:
                    fail("Rule confidence or pattern length is outside policy: " + rule_id)
                if encode_url(pattern) != encoded:
                    fail("Rule pattern must use canonical unpadded Base64URL: " + rule_id)
                if not FAMILY_RE.fullmatch(source_id) or not re.fullmatch(r"[A-Za-z0-9.+-]{1,64}", license_id):
                    fail("Every rule requires a valid source_id and license_id: " + rule_id)
                if not description or len(description) > 240:
                    fail("Rule description must be 1..240 characters: " + rule_id)
                total_pattern += len(pattern)
                if total_pattern > MAX_TOTAL_PATTERN:
                    fail("Total rule pattern bytes exceed 64 KiB.")
                rules.append({
                    "id": rule_id, "family": family, "classification": classification,
                    "confidence": confidence, "source_id": source_id, "license_id": license_id,
                    "pattern": pattern, "description": description,
                })
    except OSError as exc:
        fail("Could not read reviewed rule CSV: " + str(exc))
    if not rules or len(rules) > MAX_RULES:
        fail("Rule set must contain 1..511 rules.")
    ids = [rule["id"] for rule in rules]
    if ids != sorted(set(ids)):
        fail("Rule IDs must be sorted and unique.")
    return rules


def serialize_bundle(rules: list[dict], key, version: int, now: int) -> bytes:
    expires = now + VALIDITY
    lines = [
        HEADER, "key_id=" + KEY_ID, "version=" + str(version),
        "issued_at=" + str(now), "expires_at=" + str(expires),
    ]
    for rule in rules:
        description = rule["description"].encode("utf-8")
        lines.append("rule=" + "|".join((
            rule["id"], rule["family"], rule["classification"], str(rule["confidence"]),
            rule["source_id"], rule["license_id"], encode_url(rule["pattern"]), encode_url(description),
        )))
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    result = payload + ("signature=" + base64.b64encode(signature).decode("ascii") + "\n").encode("ascii")
    if len(result) > MAX_BYTES:
        fail("Signed content-rule bundle exceeds 1 MiB.")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--previous-version")
    parser.add_argument("--check-key-only", action="store_true")
    args = parser.parse_args()

    raw_key = os.environ.get("ALAI_FEED_SIGNING_KEY_PEM", "")
    if not raw_key:
        fail("Missing ALAI_FEED_SIGNING_KEY_PEM secret.")
    key = load_private_key(raw_key)
    if args.check_key_only:
        print("Signing key matches pinned Android public key; no rule bundle generated.")
        return
    if os.environ.get("ALAI_CONTENT_RULES_REVIEWED", "").lower() != "true":
        fail("ALAI_CONTENT_RULES_REVIEWED=true is required after manual rule review.")
    if os.environ.get("ALAI_CONTENT_RULES_COMMERCIAL_USE_APPROVED", "").lower() != "true":
        fail("Commercial redistribution rights for every rule must be confirmed first.")

    now = int(time.time())
    previous = 0
    if args.previous_version:
        try:
            previous = int(Path(args.previous_version).read_text().strip() or "0")
        except FileNotFoundError:
            previous = 0
        except Exception as exc:
            fail("Could not read prior rule version: " + str(exc))
    version = max(now, previous + 1)
    rules = read_rules(Path(args.input))
    bundle = serialize_bundle(rules, key, version, now)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(bundle)
    print(f"Signed content-rule bundle candidate: version={version} rules={len(rules)} bytes={len(bundle)}")
    print("Only reviewed metadata patterns are included; no malware samples or payloads are downloaded.")


if __name__ == "__main__":
    main()

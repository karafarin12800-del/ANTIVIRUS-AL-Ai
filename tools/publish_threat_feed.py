#!/usr/bin/env python3
"""Build a bounded, signed, typed threat-intelligence feed. Metadata only."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PUBLIC_KEY_B64 = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM1szM5WLCBP0KDTXsrVfBdPxErB4sVo4mhY+duhjfDP5MwASTx0pLor3mSL7dLRwX/gZpi6odLquz/BfIGSafg=="
)
KEY_ID = "alai-release-2026"
MB_API = "https://mb-api.abuse.ch/api/v1/"
TF_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_EXPORT = "https://urlhaus-api.abuse.ch/v2/files/exports/{}/recent.csv"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
SOURCES = ("FEODO_TRACKER", "MALWAREBAZAAR", "THREATFOX", "URLHAUS")
TYPE_LIMITS = {"SHA256": 16000, "URL": 2000, "DOMAIN": 1000, "IPV4": 500, "IP_PORT": 500}
MAX_ENTRIES = 20000
MAX_FEED_BYTES = 4 * 1024 * 1024
VALIDITY = 7 * 24 * 60 * 60


def fail(message: str) -> "NoReturn":
    print("ERROR: " + message, file=sys.stderr)
    raise SystemExit(2)


def get_bytes(url: str, headers: dict[str, str], limit: int, method: str = "GET", body: bytes | None = None) -> bytes:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            raw = response.read(limit + 1)
    except Exception as exc:
        fail("Provider request failed: " + str(exc))
    if len(raw) > limit:
        fail("Provider response exceeded its safety size limit.")
    return raw


def parse_time(value: object, fallback: int) -> int:
    if not isinstance(value, str) or not value.strip():
        return fallback
    raw = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return int(datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            pass
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return int((parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp())
    except ValueError:
        return fallback


def normalize_domain(raw: str) -> str | None:
    value = raw.strip().rstrip(".").lower()
    if not value or len(value) > 253 or "*" in value or "/" in value:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    labels = value.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return None
    return value


def normalize_url(raw: str) -> str | None:
    if not raw or len(raw) > 2048 or any(ch.isspace() or ord(ch) < 0x20 for ch in raw):
        return None
    try:
        part = urlsplit(raw.strip())
        if part.scheme.lower() not in ("http", "https") or not part.hostname:
            return None
        if part.username is not None or part.password is not None or part.fragment:
            return None
        host = part.hostname.encode("idna").decode("ascii").lower()
        if ":" in host:
            host = "[" + host + "]"
        port = part.port
        netloc = host + ((":" + str(port)) if port else "")
        result = urlunsplit((part.scheme.lower(), netloc, part.path or "/", part.query, ""))
        return result if len(result) <= 2048 else None
    except (ValueError, UnicodeError):
        return None


def normalize_ipv4(raw: str) -> str | None:
    try:
        value = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    return value.compressed if isinstance(value, ipaddress.IPv4Address) else None


def normalize_ip_port(raw: str) -> str | None:
    if raw.count(":") != 1 or raw.startswith("["):
        return None
    host, raw_port = raw.rsplit(":", 1)
    address = normalize_ipv4(host)
    if address is None or not raw_port.isdigit():
        return None
    port = int(raw_port)
    return address + ":" + str(port) if 1 <= port <= 65535 else None


def normalize(kind: str, raw: object) -> str | None:
    value = str(raw or "").strip()
    if kind == "SHA256":
        return value.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", value) else None
    if kind == "URL":
        return normalize_url(value)
    if kind == "DOMAIN":
        return normalize_domain(value)
    if kind == "IPV4":
        return normalize_ipv4(value)
    if kind == "IP_PORT":
        return normalize_ip_port(value)
    return None


def family_id(source: str, family: object) -> str:
    cleaned = re.sub(r"[^A-Z0-9._-]+", "_", str(family or "UNCLASSIFIED").upper()).strip("._-")
    return (source + "." + (cleaned[:60] or "UNCLASSIFIED"))[:80]


@dataclass
class Indicator:
    kind: str
    value: str
    family: str
    classification: str
    sources: set[str] = field(default_factory=set)
    confidence: int = 0
    first_seen: int = 0
    expires_at: int = 0


def add(entries: dict, kind: str, raw: object, family: object, classification: str,
        source: str, confidence: int, first_seen: int, expires_at: int) -> None:
    value = normalize(kind, raw)
    if value is None or source not in SOURCES or classification not in {"MALWARE", "PUA", "SUSPICIOUS"}:
        return
    if not 0 <= confidence <= 100 or first_seen <= 0 or expires_at <= first_seen:
        return
    key = (kind, value)
    label = family_id(source, family)
    existing = entries.get(key)
    if existing is None:
        entries[key] = Indicator(kind, value, label, classification, {source}, confidence, first_seen, expires_at)
        return
    existing.sources.add(source)
    if existing.family.endswith(".UNCLASSIFIED") and not label.endswith(".UNCLASSIFIED"):
        existing.family = label
    priority = {"SUSPICIOUS": 1, "PUA": 2, "MALWARE": 3}
    if priority[classification] > priority[existing.classification]:
        existing.classification = classification
    existing.confidence = max(existing.confidence, confidence)
    existing.first_seen = min(existing.first_seen, first_seen)
    existing.expires_at = max(existing.expires_at, expires_at)


def fetch_malwarebazaar(key: str) -> list[dict]:
    body = urllib.parse.urlencode({"query": "recent_detections", "hours": "168"}).encode()
    raw = get_bytes(MB_API, {
        "Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json", "User-Agent": "ANTIVIRUS-AL-AI/2.0",
    }, 4 * 1024 * 1024, "POST", body)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        fail("Malformed MalwareBazaar JSON: " + str(exc))
    if payload.get("query_status") == "no_results":
        return []
    if payload.get("query_status") != "ok" or not isinstance(payload.get("data"), list):
        fail("MalwareBazaar returned an unexpected response.")
    return payload["data"]


def fetch_threatfox(key: str) -> list[dict]:
    if not key:
        return []
    body = json.dumps({"query": "get_iocs", "days": 7}).encode()
    raw = get_bytes(TF_API, {
        "Auth-Key": key, "Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": "ANTIVIRUS-AL-AI/2.0",
    }, 4 * 1024 * 1024, "POST", body)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        fail("Malformed ThreatFox JSON: " + str(exc))
    if payload.get("query_status") == "no_result":
        return []
    if payload.get("query_status") != "ok" or not isinstance(payload.get("data"), list):
        fail("ThreatFox returned an unexpected response.")
    return payload["data"]


def fetch_urlhaus(key: str) -> list[dict]:
    if not key:
        return []
    url = URLHAUS_EXPORT.format(urllib.parse.quote(key, safe=""))
    raw = get_bytes(url, {"Accept": "text/csv", "User-Agent": "ANTIVIRUS-AL-AI/2.0"}, 6 * 1024 * 1024)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        fail("URLhaus export is not UTF-8: " + str(exc))
    lines = [line for line in text.splitlines() if line.strip()]
    header_at = next((i for i, line in enumerate(lines) if "url_status" in line.lower() and "url" in line.lower()), None)
    if header_at is None:
        fail("URLhaus export has no expected URL/status header.")
    lines = lines[header_at:]
    lines[0] = lines[0].lstrip().removeprefix("#").lstrip()
    return [{
        str(k).strip().lstrip("#").strip().lower(): (v or "").strip()
        for k, v in row.items()
    } for row in csv.DictReader(lines)]


def fetch_feodo() -> list[dict]:
    raw = get_bytes(FEODO_URL, {"Accept": "application/json", "User-Agent": "ANTIVIRUS-AL-AI/2.0"}, 2 * 1024 * 1024)
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        fail("Malformed Feodo Tracker JSON: " + str(exc))
    if not isinstance(data, list):
        fail("Feodo Tracker response must be a JSON array.")
    return data


def make_entries(mb: list[dict], tf: list[dict] | None = None,
                 urlhaus: list[dict] | None = None, feodo: list[dict] | None = None,
                 now: int | None = None) -> list[Indicator]:
    now = int(now if now is not None else time.time())
    entries: dict[tuple[str, str], Indicator] = {}
    for row in mb:
        if isinstance(row, dict) and row.get("signature"):
            seen = parse_time(row.get("first_seen"), now)
            add(entries, "SHA256", row.get("sha256_hash"), row.get("signature"),
                "MALWARE", "MALWAREBAZAAR", 100, seen, now + VALIDITY)

    type_map = {
        "sha256_hash": "SHA256", "url": "URL", "domain": "DOMAIN",
        "ip": "IPV4", "ipv4": "IPV4", "ip:port": "IP_PORT",
    }
    for row in tf or []:
        if not isinstance(row, dict):
            continue
        source_type = str(row.get("ioc_type", "")).lower()
        kind = type_map.get(source_type)
        seen = parse_time(row.get("first_seen"), now)
        try:
            confidence = max(0, min(100, int(row.get("confidence_level", 50))))
        except (TypeError, ValueError):
            confidence = 50
        malware = row.get("malware_printable") or row.get("malware") or "UNCLASSIFIED"
        if kind:
            add(entries, kind, row.get("ioc"), malware,
                "MALWARE" if kind == "SHA256" else "SUSPICIOUS",
                "THREATFOX", confidence, seen, now + VALIDITY)
        for sample in row.get("malware_samples") or []:
            if isinstance(sample, dict):
                add(entries, "SHA256", sample.get("sha256_hash"), malware, "MALWARE",
                    "THREATFOX", confidence, seen, now + VALIDITY)

    for row in urlhaus or []:
        if isinstance(row, dict) and str(row.get("url_status", "")).lower() in {"online", "active"}:
            seen = parse_time(row.get("dateadded"), now)
            add(entries, "URL", row.get("url"), row.get("threat") or "MALWARE_DOWNLOAD",
                "MALWARE", "URLHAUS", 95, seen, now + 24 * 60 * 60)

    for row in feodo or []:
        if isinstance(row, dict) and str(row.get("status", "")).lower() == "online":
            seen = parse_time(row.get("first_seen"), now)
            add(entries, "IPV4", row.get("ip_address"), row.get("malware") or "UNCLASSIFIED",
                "SUSPICIOUS", "FEODO_TRACKER", 95, seen, now + 24 * 60 * 60)
    return list(entries.values())


def select_entries(entries: list[Indicator]) -> tuple[list[Indicator], bool]:
    output: list[Indicator] = []
    truncated = False
    for kind, limit in TYPE_LIMITS.items():
        group = [entry for entry in entries if entry.kind == kind]
        group.sort(key=lambda e: (-e.confidence, -e.expires_at, e.value))
        truncated = truncated or len(group) > limit
        output.extend(group[:limit])
    output.sort(key=lambda e: (e.kind, e.value))
    if len(output) > MAX_ENTRIES:
        output = output[:MAX_ENTRIES]
        truncated = True
    return output, truncated


def encode_value(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode("ascii").rstrip("=")


def serialize_feed(entries: list[Indicator], key, version: int, now: int, truncated: bool) -> bytes:
    expires = now + VALIDITY
    counts = {source: 0 for source in SOURCES}
    for entry in entries:
        for source in entry.sources:
            counts[source] += 1
    lines = [
        "ALAI-THREAT-FEED/2", "key_id=" + KEY_ID, "version=" + str(version),
        "issued_at=" + str(now), "expires_at=" + str(expires),
    ]
    for source in sorted(counts):
        lines.append("source_count=" + source + "|" + str(counts[source]))
    lines.append("feed_truncated=" + ("1" if truncated else "0"))
    for entry in sorted(entries, key=lambda e: (e.kind, e.value)):
        lines.append("entry=" + "|".join((
            entry.kind, encode_value(entry.value), entry.family, entry.classification,
            ",".join(sorted(entry.sources)), str(entry.confidence),
            str(min(entry.first_seen, now)), str(min(entry.expires_at, expires)),
        )))
    payload = ("\n".join(lines) + "\n").encode()
    signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    result = payload + ("signature=" + base64.b64encode(signature).decode() + "\n").encode()
    if len(result) > MAX_FEED_BYTES:
        fail("Generated feed exceeds Android's 4 MiB limit.")
    return result


def load_private_key(raw: str):
    try:
        key = serialization.load_pem_private_key(raw.encode(), password=None)
    except Exception as exc:
        fail("ALAI_FEED_SIGNING_KEY_PEM is invalid: " + str(exc))
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        fail("Feed signing key must be ECDSA P-256.")
    derived = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    actual = base64.b64encode(derived).decode()
    if actual != PUBLIC_KEY_B64:
        print("Configured public-key SHA-256: " + hashlib.sha256(derived).hexdigest(), file=sys.stderr)
        fail("Private signing key does not match Android's pinned public key.")
    return key


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--previous-version")
    parser.add_argument("--check-key-only", action="store_true")
    args = parser.parse_args()

    raw_key = os.environ.get("ALAI_FEED_SIGNING_KEY_PEM", "")
    if not raw_key:
        fail("Missing ALAI_FEED_SIGNING_KEY_PEM secret.")
    key = load_private_key(raw_key)
    if args.check_key_only:
        print("Signing key matches. No provider was contacted; no feed generated.")
        return

    abusech_ok = os.environ.get("ALAI_ABUSECH_COMMERCIAL_USE_APPROVED", "").lower() == "true"
    mb_key = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "").strip()
    tf_key = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
    urlhaus_key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    urlhaus_ok = os.environ.get("ALAI_URLHAUS_COMMERCIAL_USE_APPROVED", "").lower() == "true"
    feodo_enabled = os.environ.get("ALAI_ENABLE_FEODO_TRACKER", "true").lower() == "true"

    if not abusech_ok:
        fail("MalwareBazaar/ThreatFox require verified commercial-use entitlement before publishing.")
    if not mb_key:
        fail("Missing MALWAREBAZAAR_AUTH_KEY.")
    if urlhaus_key and not (abusech_ok and urlhaus_ok):
        fail("URLhaus key is configured but separate URLhaus commercial approval is missing.")
    if urlhaus_ok and not urlhaus_key:
        fail("URLhaus approval is set but URLHAUS_AUTH_KEY is missing.")

    now = int(time.time())
    mb = fetch_malwarebazaar(mb_key)
    tf = fetch_threatfox(tf_key)
    uh = fetch_urlhaus(urlhaus_key)
    feodo = fetch_feodo() if feodo_enabled else []
    entries, truncated = select_entries(make_entries(mb, tf, uh, feodo, now))
    if not entries:
        fail("No valid indicators from the configured sources; refusing to publish an empty feed.")

    previous = 0
    if args.previous_version:
        try:
            previous = int(Path(args.previous_version).read_text().strip() or "0")
        except FileNotFoundError:
            previous = 0
        except Exception as exc:
            fail("Could not read prior feed version: " + str(exc))
    version = max(now, previous + 1)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(serialize_feed(entries, key, version, now, truncated))

    counts = {source: 0 for source in SOURCES}
    for entry in entries:
        for source in entry.sources:
            counts[source] += 1
    print("Signed feed candidate: version=" + str(version) + " indicators=" + str(len(entries))
          + " truncated=" + str(truncated).lower())
    print("Source coverage: " + json.dumps(counts, sort_keys=True))
    print("Metadata only; no malware samples or payloads downloaded.")


if __name__ == "__main__":
    main()

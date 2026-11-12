import unittest
import publish_threat_feed as publisher

NOW = 1_800_000_000
HASH_A = "a" * 64
HASH_B = "b" * 64


class ThreatFeedTests(unittest.TestCase):
    def test_threatfox_imports_typed_iocs_and_hashes(self):
        rows = [
            {"ioc_type": "domain", "ioc": "Bad.Example.", "malware": "win.test", "confidence_level": 90},
            {"ioc_type": "url", "ioc": "https://download.example/payload", "malware": "win.test"},
            {"ioc_type": "ip:port", "ioc": "203.0.113.9:443", "malware": "win.test"},
            {"ioc_type": "sha256_hash", "ioc": HASH_A, "malware": "win.test", "malware_samples": [{"sha256_hash": HASH_B}]},
        ]
        keys = {(x.kind, x.value) for x in publisher.make_entries([], rows, now=NOW)}
        self.assertIn(("DOMAIN", "bad.example"), keys)
        self.assertIn(("URL", "https://download.example/payload"), keys)
        self.assertIn(("IP_PORT", "203.0.113.9:443"), keys)
        self.assertIn(("SHA256", HASH_A), keys)
        self.assertIn(("SHA256", HASH_B), keys)

    def test_dedup_preserves_source_provenance(self):
        entries = publisher.make_entries(
            [{"sha256_hash": HASH_A, "signature": "Test.Family"}],
            [{"ioc_type": "sha256_hash", "ioc": HASH_A, "malware": "other.family", "confidence_level": 80}],
            now=NOW,
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].sources, {"MALWAREBAZAAR", "THREATFOX"})
        self.assertEqual(entries[0].confidence, 100)

    def test_urlhaus_only_imports_active_urls(self):
        entries = publisher.make_entries([], urlhaus=[
            {"url": "https://active.example/a", "url_status": "online"},
            {"url": "https://offline.example/a", "url_status": "offline"},
        ], now=NOW)
        self.assertEqual([x.value for x in entries], ["https://active.example/a"])

    def test_feodo_only_imports_online_ipv4(self):
        entries = publisher.make_entries([], feodo=[
            {"ip_address": "203.0.113.10", "status": "online", "malware": "Qakbot"},
            {"ip_address": "203.0.113.11", "status": "offline", "malware": "Qakbot"},
        ], now=NOW)
        self.assertEqual([(x.kind, x.value) for x in entries], [("IPV4", "203.0.113.10")])

    def test_invalid_values_are_rejected(self):
        entries = publisher.make_entries([], [
            {"ioc_type": "sha256_hash", "ioc": "bad"},
            {"ioc_type": "domain", "ioc": "not..valid"},
            {"ioc_type": "url", "ioc": "file:///tmp/a"},
            {"ioc_type": "ip:port", "ioc": "999.999.999.999:443"},
        ], now=NOW)
        self.assertEqual(entries, [])

    def test_per_type_caps_are_enforced(self):
        entries = [
            publisher.Indicator("SHA256", format(i, "064x"), "TEST.FAMILY", "MALWARE",
                                {"MALWAREBAZAAR"}, 90, NOW - 5, NOW + 500)
            for i in range(publisher.TYPE_LIMITS["SHA256"] + 1)
        ]
        selected, truncated = publisher.select_entries(entries)
        self.assertTrue(truncated)
        self.assertEqual(len(selected), publisher.TYPE_LIMITS["SHA256"])

    def test_v2_serialization_includes_source_metadata(self):
        item = publisher.Indicator("DOMAIN", "bad.example", "THREATFOX.TEST", "SUSPICIOUS",
                                   {"THREATFOX"}, 90, NOW - 10, NOW + 3600)
        class FakeKey:
            def sign(self, payload, algorithm):
                return b"test-signature"
        encoded = publisher.serialize_feed([item], FakeKey(), 100, NOW, False).decode()
        self.assertIn("ALAI-THREAT-FEED/2\n", encoded)
        self.assertIn("source_count=THREATFOX|1\n", encoded)
        self.assertIn("feed_truncated=0\n", encoded)
        self.assertIn("entry=DOMAIN|", encoded)


if __name__ == "__main__":
    unittest.main()

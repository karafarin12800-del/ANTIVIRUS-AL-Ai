import contextlib
import io
import unittest

import publish_threat_feed as publisher


class ThreatFeedEntryTests(unittest.TestCase):
    def test_merges_malwarebazaar_and_threatfox_sample_hashes(self):
        bazaar_hash = "a" * 64
        threatfox_hash = "b" * 64
        shared_hash = "c" * 64
        entries = publisher.make_entries(
            [
                {"sha256_hash": bazaar_hash, "signature": "Android.TestFamily"},
                {"sha256_hash": shared_hash, "signature": "Bazaar.Family"},
            ],
            [
                {
                    "malware": "android.threatfox_family",
                    "malware_samples": [
                        {"sha256_hash": threatfox_hash},
                        {"sha256_hash": shared_hash},
                    ],
                }
            ],
        )
        by_hash = {sha: (family, classification) for sha, family, classification in entries}
        self.assertEqual(len(entries), 3)
        self.assertEqual(by_hash[bazaar_hash], ("MALWAREBAZAAR.ANDROID.TESTFAMILY", "MALWARE"))
        self.assertEqual(by_hash[threatfox_hash], ("THREATFOX.ANDROID.THREATFOX_FAMILY", "MALWARE"))
        self.assertEqual(by_hash[shared_hash], ("MALWAREBAZAAR.BAZAAR.FAMILY", "MALWARE"))

    def test_rejects_feed_with_no_valid_hashes(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                publisher.make_entries(
                    [
                        {"sha256_hash": "not-a-sha256", "signature": "bad"},
                        {"sha256_hash": "d" * 64, "signature": ""},
                    ],
                    [
                        {"malware": "family.without.sample.hash", "malware_samples": [{"sha256_hash": "bad"}]},
                        {"malware": "", "malware_samples": [{"sha256_hash": "e" * 64}]},
                    ],
                )


if __name__ == "__main__":
    unittest.main()

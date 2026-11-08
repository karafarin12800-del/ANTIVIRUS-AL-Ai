import base64
import unittest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import publish_content_rules as publisher


class PublishContentRulesTests(unittest.TestCase):
    def test_serialized_bundle_signature_verifies_with_signing_key(self):
        key = ec.generate_private_key(ec.SECP256R1())
        rule = {
            "id": "RULE-001",
            "family": "TEST_FAMILY",
            "group_id": "TEST_GROUP",
            "min_group_matches": 1,
            "classification": "SUSPICIOUS",
            "confidence": 50,
            "source_id": "INTERNAL_TEST_SOURCE",
            "license_id": "MIT",
            "pattern": b"SAFE_TEST_PATTERN",
            "description": "Harmless test pattern only.",
        }
        now = 1_800_000_000
        bundle = publisher.serialize_bundle([rule], key, 42, now)
        lines = bundle.decode("utf-8").splitlines()
        self.assertEqual(lines[0], publisher.HEADER)
        self.assertEqual(publisher.HEADER, "ALAI-CONTENT-RULES/2")
        fields = lines[5].removeprefix("rule=").split("|")
        self.assertEqual(len(fields), 10)
        self.assertEqual(fields[2], "TEST_GROUP")
        self.assertEqual(fields[3], "1")
        self.assertTrue(lines[-1].startswith("signature="))
        payload = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
        signature = base64.b64decode(lines[-1].split("=", 1)[1])
        key.public_key().verify(signature, payload, ec.ECDSA(hashes.SHA256()))

    def test_url_base64_encoding_is_canonical(self):
        raw = b"content-pattern-01"
        encoded = publisher.encode_url(raw)
        self.assertNotIn("=", encoded)
        self.assertEqual(base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4)), raw)

    def test_group_threshold_must_fit_available_rules(self):
        rules = [{
            "group_id": "FALLSPY_GROUP",
            "family": "FALLSPY_ANDROID",
            "min_group_matches": 4,
            "classification": "SUSPICIOUS",
            "confidence": 75,
            "source_id": "WITHSECURELABS_IOCS",
            "license_id": "BSD-2-Clause",
        }] * 3
        with self.assertRaises(SystemExit):
            publisher.validate_group_metadata(rules)

    def test_group_metadata_must_be_consistent(self):
        rules = [{
            "group_id": "FALLSPY_GROUP",
            "family": "FALLSPY_ANDROID",
            "min_group_matches": 2,
            "classification": "SUSPICIOUS",
            "confidence": 75,
            "source_id": "WITHSECURELABS_IOCS",
            "license_id": "BSD-2-Clause",
        }, {
            "group_id": "FALLSPY_GROUP",
            "family": "FALLSPY_ANDROID",
            "min_group_matches": 1,
            "classification": "SUSPICIOUS",
            "confidence": 75,
            "source_id": "WITHSECURELABS_IOCS",
            "license_id": "BSD-2-Clause",
        }]
        with self.assertRaises(SystemExit):
            publisher.validate_group_metadata(rules)


if __name__ == "__main__":
    unittest.main()

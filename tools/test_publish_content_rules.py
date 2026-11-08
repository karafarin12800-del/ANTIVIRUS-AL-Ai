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
        self.assertTrue(lines[-1].startswith("signature="))
        payload = ("\n".join(lines[:-1]) + "\n").encode("utf-8")
        signature = base64.b64decode(lines[-1].split("=", 1)[1])
        key.public_key().verify(signature, payload, ec.ECDSA(hashes.SHA256()))

    def test_url_base64_encoding_is_canonical(self):
        raw = b"content-pattern-01"
        encoded = publisher.encode_url(raw)
        self.assertNotIn("=", encoded)
        self.assertEqual(base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4)), raw)


if __name__ == "__main__":
    unittest.main()

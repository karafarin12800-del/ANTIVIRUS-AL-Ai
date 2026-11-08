package com.antivirusalai.intel

import org.junit.Assert.assertThrows
import org.junit.Test

class ContentRuleBundleParserTest {
    @Test
    fun rejectsUnsupportedHeaderBeforeTrustingRules() {
        assertThrows(IllegalArgumentException::class.java) {
            ContentRuleBundleParser.parse("NOT-A-RULE-BUNDLE\n".toByteArray())
        }
    }

    @Test
    fun rejectsOversizedBundle() {
        val oversized = ByteArray(ContentRuleBundleParser.MAX_BUNDLE_BYTES + 1)
        assertThrows(IllegalArgumentException::class.java) {
            ContentRuleBundleParser.parse(oversized)
        }
    }

    @Test
    fun rejectsUnsignedBundle() {
        val payload = listOf(
            ContentRuleBundleParser.HEADER,
            "key_id=alai-release-2026",
            "version=1",
            "issued_at=1800000000",
            "expires_at=1800003600",
            "rule=TEST|TEST|SUSPICIOUS|50|VEVTVF9QQVRURVJO|SGFybWxlc3MgdGVzdC4"
        ).joinToString("\n", postfix = "\n")
        val unsigned = (payload + "signature=AA==\n").toByteArray()
        assertThrows(IllegalArgumentException::class.java) {
            ContentRuleBundleParser.parse(unsigned, nowEpochSeconds = 1800000100L)
        }
    }
}

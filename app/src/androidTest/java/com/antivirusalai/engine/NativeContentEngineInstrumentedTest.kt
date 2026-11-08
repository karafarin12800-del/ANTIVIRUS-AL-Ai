package com.antivirusalai.engine

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeContentEngineInstrumentedTest {
    @Test
    fun nativeLibraryLoadsAndFindsRuleSplitAcrossChunks() {
        val session = NativeContentEngine.openSession()
        assertNotNull("The Android package must contain libalai_scan_engine.so.", session)
        session!!.use { scanner ->
            val marker = NativeContentEngine.SELF_TEST_MARKER.toByteArray(Charsets.US_ASCII)
            val split = marker.size / 2
            scanner.update(marker.copyOfRange(0, split), split)
            val tail = marker.copyOfRange(split, marker.size)
            scanner.update(tail, tail.size)
            assertEquals(setOf(NativeContentEngine.SELF_TEST_RULE_ID), scanner.finish())
        }
    }

    @Test
    fun nativeLibraryFindsCustomContentRule() {
        val rule = ContentSignatureRule(
            id = "INTERNAL-TEST-RULE",
            familyId = "TEST",
            classification = com.antivirusalai.intel.ThreatClassification.SUSPICIOUS,
            confidence = 50,
            pattern = "CUSTOM_PATTERN_123".toByteArray(Charsets.US_ASCII),
            description = "Harmless custom rule fixture."
        )
        val session = NativeContentEngine.openSession(listOf(rule))
        assertNotNull(session)
        session!!.use { scanner ->
            val first = "prefix-CUSTOM_".toByteArray(Charsets.US_ASCII)
            val second = "PATTERN_123-suffix".toByteArray(Charsets.US_ASCII)
            scanner.update(first, first.size)
            scanner.update(second, second.size)
            assertEquals(setOf("INTERNAL-TEST-RULE"), scanner.finish())
        }
    }

    @Test
    fun nativeLibraryDoesNotMatchOrdinaryText() {
        val session = NativeContentEngine.openSession()
        assertNotNull(session)
        session!!.use { scanner ->
            val bytes = "ordinary document contents".toByteArray(Charsets.UTF_8)
            scanner.update(bytes, bytes.size)
            assertEquals(emptySet<String>(), scanner.finish())
        }
    }
}

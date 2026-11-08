package com.antivirusalai.engine

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeContentEngineInstrumentedTest {
    @Test
    fun nativeLibraryLoadsAndFindsMarkerSplitAcrossChunks() {
        val session = NativeContentEngine.openSession()
        assertNotNull("The Android package must contain libalai_scan_engine.so.", session)

        session!!.use { scanner ->
            val prefix = "prefix:".toByteArray(Charsets.US_ASCII)
            val marker = NativeContentEngine.SELF_TEST_MARKER.toByteArray(Charsets.US_ASCII)
            scanner.update(prefix, prefix.size)
            val split = marker.size / 2
            scanner.update(marker.copyOfRange(0, split), split)
            val remaining = marker.copyOfRange(split, marker.size)
            scanner.update(remaining, remaining.size)
            assertEquals(
                NativeContentEngine.RESULT_SELF_TEST_MATCH,
                scanner.finish()
            )
        }
    }

    @Test
    fun nativeLibraryDoesNotMatchOrdinaryText() {
        val session = NativeContentEngine.openSession()
        assertNotNull("The Android package must contain libalai_scan_engine.so.", session)

        session!!.use { scanner ->
            val bytes = "ordinary document contents".toByteArray(Charsets.UTF_8)
            scanner.update(bytes, bytes.size)
            assertEquals(NativeContentEngine.RESULT_NO_MATCH, scanner.finish())
        }
    }
}

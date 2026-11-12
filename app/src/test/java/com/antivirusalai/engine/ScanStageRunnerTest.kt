package com.antivirusalai.engine

import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanStageRunnerTest {
    @Test
    fun failedStageDoesNotPreventIndependentFallbackStage() {
        var fallbackExecuted = false

        val primary = ScanStageRunner.execute("NATIVE_SIGNATURES") {
            throw IllegalStateException("simulated engine fault")
        }
        val fallback = ScanStageRunner.execute("HASH_REPUTATION_FALLBACK") {
            fallbackExecuted = true
            "sha256-complete"
        }

        assertFalse(primary.completed)
        assertEquals("ILLEGALSTATEEXCEPTION", primary.failureCode)
        assertNull(primary.value)
        assertTrue(fallback.completed)
        assertEquals("sha256-complete", fallback.value)
        assertTrue(fallbackExecuted)
        assertNotNull(ScanStageRunner.failureEvidence(primary))
        assertNull(ScanStageRunner.failureEvidence(fallback))
    }

    @Test
    fun linkageFailureIsIsolated() {
        val result = ScanStageRunner.execute("NATIVE_JNI") {
            throw UnsatisfiedLinkError("missing native library")
        }

        assertFalse(result.completed)
        assertEquals("LINKAGE_ERROR", result.failureCode)
    }

    @Test
    fun cancellationIsNeverConvertedIntoAnEngineFailure() {
        assertThrows(CancellationException::class.java) {
            ScanStageRunner.execute("CANCELLABLE_STAGE") {
                throw CancellationException("scan cancelled")
            }
        }
    }

    @Test
    fun successfulNullableStageIsDifferentFromFailedStage() {
        val result = ScanStageRunner.execute<String?>("APK_METADATA") { null }

        assertTrue(result.completed)
        assertNull(result.value)
        assertNull(result.failureCode)
    }
}

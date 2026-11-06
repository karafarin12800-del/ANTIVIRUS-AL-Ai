package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class EicarTestDetectorTest {
    private val eicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}\\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\\$H+H*"

    @Test
    fun detectsHarmlessEicarStringWhenSplitAcrossReadBoundaries() {
        val bytes = ("x".repeat(9000) + eicar + "tail").toByteArray(Charsets.US_ASCII)
        assertTrue(EicarTestDetector.contains(ByteArrayInputStream(bytes)))
    }

    @Test
    fun rejectsPlainTextAndNearMiss() {
        assertFalse(EicarTestDetector.contains(ByteArrayInputStream("ordinary text".toByteArray())))
        assertFalse(EicarTestDetector.contains(ByteArrayInputStream(eicar.dropLast(1).toByteArray())))
    }

    @Test
    fun usesTheStandardEicarTestStringLength() {
        assertEquals(68, eicar.length)
    }
}

package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class EicarTestDetectorTest {
    private val eicar = buildString {
        append("X5O!P%@AP[4\\PZX54(P^)7}")
        append('$')
        append("EICAR-STANDARD-ANTIVIRUS-TEST-FILE!")
        append('$')
        append("H+H*")
    }

    @Test
    fun detectsHarmlessEicarStringWhenSplitAcrossReadBoundaries() {
        val prefixLength = 8192 - 17
        val bytes = ("x".repeat(prefixLength) + eicar + "tail").toByteArray(Charsets.US_ASCII)
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

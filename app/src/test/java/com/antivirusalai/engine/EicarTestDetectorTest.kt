package com.antivirusalai.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class EicarTestDetectorTest {
    private val eicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}" + '

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
        assertTrue(eicar.length == 68)
    }
}
 +
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + '

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
        assertTrue(eicar.length == 68)
    }
}
 + "H+H*"

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
        assertTrue(eicar.length == 68)
    }
}

package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class Sha256Test {
    @Test
    fun hashesKnownUtf8Input() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Sha256.digest("abc".toByteArray(Charsets.UTF_8))
        )
    }

    @Test
    fun outputIsLowercaseHex() {
        val actual = Sha256.digest(byteArrayOf(0, 1, 15, 16, -1))
        assertEquals(64, actual.length)
        assertEquals(actual.lowercase(), actual)
        assertTrue(actual.all { it in "0123456789abcdef" })
    }
}

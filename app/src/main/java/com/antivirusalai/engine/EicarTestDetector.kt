package com.antivirusalai.engine

import java.io.File
import java.io.InputStream

/**
 * Recognizes the harmless EICAR antivirus test string.
 *
 * This is a regression-test marker only. It is not a production malware signature
 * and must never be presented as evidence of real-world malware detection.
 */
object EicarTestDetector {
    private val pattern: ByteArray = buildString {
        append("X5O!P%@AP[4\\PZX54(P^)7CC)7}")
        append('$')
        append("EICAR-STANDARD-ANTIVIRUS-TEST-FILE!")
        append('$')
        append("H+H*")
    }.toByteArray(Charsets.US_ASCII)

    private val prefix: IntArray = IntArray(pattern.size).also { table ->
        var matched = 0
        for (i in 1 until pattern.size) {
            while (matched > 0 && pattern[i] != pattern[matched]) {
                matched = table[matched - 1]
            }
            if (pattern[i] == pattern[matched]) matched++
            table[i] = matched
        }
    }

    fun contains(file: File): Boolean = file.inputStream().use(::contains)

    /** Streaming KMP matcher; memory use is constant regardless of file size. */
    fun contains(input: InputStream): Boolean {
        var matched = 0
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) return false
            if (count == 0) continue

            for (i in 0 until count) {
                val value = buffer[i]
                while (matched > 0 && value != pattern[matched]) {
                    matched = prefix[matched - 1]
                }
                if (value == pattern[matched]) matched++
                if (matched == pattern.size) return true
            }
        }
    }
}

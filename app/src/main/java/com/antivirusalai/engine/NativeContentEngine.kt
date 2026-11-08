package com.antivirusalai.engine

/**
 * Thin JNI boundary for the on-device C++ streaming matcher.
 *
 * The initial built-in rule set is deliberately test-only: it recognizes one
 * harmless marker and must never be represented as a malware signature set.
 */
object NativeContentEngine {
    const val RULE_SET_ID = "builtin-selftest-only-v1"
    const val SELF_TEST_RULE_ID = "ALAI-NATIVE-ENGINE-SELFTEST"
    const val SELF_TEST_MARKER = "ALAI_ENGINE_SELFTEST_MARKER_V1"

    const val RESULT_NO_MATCH = 0
    const val RESULT_SELF_TEST_MATCH = 1

    private val libraryLoaded: Boolean = try {
        System.loadLibrary("alai_scan_engine")
        true
    } catch (_: LinkageError) {
        false
    } catch (_: SecurityException) {
        false
    }

    fun openSession(): Session? {
        if (!libraryLoaded) return null
        val handle = try {
            nativeCreate()
        } catch (_: LinkageError) {
            0L
        }
        return if (handle == 0L) null else Session(handle)
    }

    class Session internal constructor(private var handle: Long) : AutoCloseable {
        fun update(buffer: ByteArray, length: Int) {
            check(handle != 0L) { "Native scan session is closed." }
            require(length in 0..buffer.size) { "Invalid native scan chunk length." }
            check(NativeContentEngine.nativeUpdate(handle, buffer, length)) {
                "Native scanner rejected the input chunk."
            }
        }

        fun finish(): Int {
            check(handle != 0L) { "Native scan session is closed." }
            val result = NativeContentEngine.nativeFinish(handle)
            check(result == RESULT_NO_MATCH || result == RESULT_SELF_TEST_MATCH) {
                "Native scanner returned an invalid result."
            }
            return result
        }

        override fun close() {
            val activeHandle = handle
            if (activeHandle != 0L) {
                handle = 0L
                NativeContentEngine.nativeDestroy(activeHandle)
            }
        }
    }

    private external fun nativeCreate(): Long
    private external fun nativeUpdate(handle: Long, buffer: ByteArray, length: Int): Boolean
    private external fun nativeFinish(handle: Long): Int
    private external fun nativeDestroy(handle: Long)
}

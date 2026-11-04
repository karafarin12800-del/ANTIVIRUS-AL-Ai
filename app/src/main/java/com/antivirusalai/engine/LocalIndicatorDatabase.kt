package com.antivirusalai.engine

/**
 * No production malware signatures are bundled in this MVP.
 * This one benign fixture verifies that hashing and exact-match reporting work.
 */
object LocalIndicatorDatabase {
    const val BENIGN_TEST_MARKER_SHA256 =
        "06093b424ea3e8c5808b723e37efc3d7e69b3b8d0596e60b3eb718d95bb6955f"

    enum class Match { BENIGN_PROJECT_TEST_MARKER }

    fun lookup(sha256: String): Match? =
        if (sha256.equals(BENIGN_TEST_MARKER_SHA256, ignoreCase = true)) {
            Match.BENIGN_PROJECT_TEST_MARKER
        } else null
}

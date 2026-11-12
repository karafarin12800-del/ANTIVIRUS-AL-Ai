package com.antivirusalai.engine

/**
 * Explicit resource ceilings for scans. Reaching a ceiling must produce an
 * incomplete report; it must never be presented as a complete clean result.
 */
object ScanLimits {
    const val QUICK_FILE_LIMIT = 350
    const val QUICK_TOTAL_BYTES = 1024L * 1024L * 1024L

    const val DEEP_FILE_LIMIT = 100_000
    const val DEEP_TOTAL_BYTES = 25L * 1024L * 1024L * 1024L

    const val FOLDER_FILE_LIMIT = 100_000
    const val FOLDER_TOTAL_BYTES = 25L * 1024L * 1024L * 1024L

    const val MAX_FILE_DEPTH = 64
    const val MAX_DIRECTORY_VISITS = 20_000
    const val MAX_QUICK_DIRECTORY_VISITS = 3_000
    const val MAX_FOLDER_DIRECTORY_VISITS = 20_000
    const val MAX_PENDING_DIRECTORIES = 30_000
    const val MAX_RESULT_DETAILS = 60
}

package com.antivirusalai.engine

import java.io.File

/** Result of adding the readable package APK components to a scan candidate set. */
internal data class PackageArchiveCollection(
    val addedComponents: Int,
    val skippedComponents: Int
)

/**
 * Adds each readable base/split APK once. Missing or unreadable components are
 * counted separately so a readable base APK cannot hide an unchecked split.
 */
internal object InstalledPackageArchiveCollector {
    fun collect(
        paths: List<String?>,
        output: LinkedHashMap<String, File>,
        maxFiles: Int
    ): PackageArchiveCollection {
        require(maxFiles > 0) { "The package candidate limit must be positive." }
        var added = 0
        var skipped = 0

        for (path in paths) {
            // Once the overall candidate cap is reached, the caller reports a
            // traversal truncation. Do not turn every remaining path into a
            // per-component skip as the remaining inventory was not enumerated.
            if (output.size >= maxFiles) break

            if (path.isNullOrBlank()) {
                skipped++
                continue
            }

            val file = File(path)
            if (!file.isFile || !file.canRead()) {
                skipped++
                continue
            }

            val canonical = runCatching { file.canonicalFile }.getOrNull()
            if (canonical == null) {
                skipped++
                continue
            }

            if (output.putIfAbsent(canonical.path, canonical) == null) {
                added++
            }
        }

        return PackageArchiveCollection(added, skipped)
    }
}

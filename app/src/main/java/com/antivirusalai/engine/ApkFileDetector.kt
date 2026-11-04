package com.antivirusalai.engine

import java.io.File
import java.util.zip.ZipFile

/**
 * APKs are ZIP containers with a compiled AndroidManifest.xml at the archive root.
 * This detects renamed APK files without extracting or executing archive contents.
 * PackageManager remains responsible for validating/parsing the package metadata.
 */
object ApkFileDetector {
    fun isApkArchive(file: File): Boolean {
        if (!file.isFile || file.length() < 4L) return false
        return try {
            ZipFile(file).use { archive ->
                archive.getEntry("AndroidManifest.xml") != null
            }
        } catch (_: Exception) {
            false
        }
    }
}

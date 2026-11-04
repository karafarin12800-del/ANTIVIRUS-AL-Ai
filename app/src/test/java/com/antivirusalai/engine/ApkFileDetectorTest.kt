package com.antivirusalai.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkFileDetectorTest {
    @Test
    fun recognizesApkByRootManifestEvenWhenExtensionIsChanged() {
        val file = File.createTempFile("renamed-apk-", ".data")
        try {
            ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(byteArrayOf(1, 2, 3))
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(byteArrayOf(4, 5, 6))
                zip.closeEntry()
            }
            assertTrue(ApkFileDetector.isApkArchive(file))
        } finally {
            file.delete()
        }
    }

    @Test
    fun rejectsOrdinaryZipWithoutAndroidManifest() {
        val file = File.createTempFile("ordinary-archive-", ".zip")
        try {
            ZipOutputStream(file.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("readme.txt"))
                zip.write("not an apk".toByteArray())
                zip.closeEntry()
            }
            assertFalse(ApkFileDetector.isApkArchive(file))
        } finally {
            file.delete()
        }
    }

    @Test
    fun rejectsNonZipFile() {
        val file = File.createTempFile("not-zip-", ".bin")
        try {
            file.writeText("plain text")
            assertFalse(ApkFileDetector.isApkArchive(file))
        } finally {
            file.delete()
        }
    }
}

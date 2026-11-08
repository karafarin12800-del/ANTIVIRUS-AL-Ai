package com.antivirusalai.engine

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class FormatStaticAnalyzerTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test
    fun parsesDexHeaderAndFindsStaticApiReferences() {
        val dex = ByteArray(256)
        byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00).copyInto(dex)
        ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(32, dex.size)
            putInt(36, 0x70)
            putInt(40, 0x12345678)
        }
        "java/lang/ProcessBuilder".toByteArray(Charsets.US_ASCII).copyInto(dex, 0x70)
        val apk = zip("sample.apk", "classes.dex" to dex)
        val report = FormatStaticAnalyzer.analyze(apk)
        assertTrue(report.supported)
        assertTrue(report.complete)
        assertTrue(report.signalCategories.contains("PROCESS_EXECUTION"))
        assertTrue(report.evidence.any { it.code == "DEX_PROCESS_BUILDER_API" })
    }

    @Test
    fun flagsUnsafeArchivePathWithoutExtractingIt() {
        val archive = zip("paths.zip", "../outside.txt" to "not-extracted".toByteArray())
        val report = FormatStaticAnalyzer.analyze(archive)
        assertTrue(report.supported)
        assertTrue(report.signalCategories.contains("ARCHIVE_ANOMALY"))
        assertTrue(report.evidence.any { it.code == "ARCHIVE_PATH_TRAVERSAL_NAME" })
    }

    @Test
    fun inspectsElfHeaderWithoutLoadingNativeCode() {
        val elf = ByteArray(64)
        elf[0] = 0x7f
        elf[1] = 'E'.code.toByte()
        elf[2] = 'L'.code.toByte()
        elf[3] = 'F'.code.toByte()
        elf[4] = 2
        elf[5] = 1
        elf[18] = 183.toByte()
        "execve".toByteArray(Charsets.US_ASCII).copyInto(elf, 32)
        val file = temporary.newFile("libsample.so")
        file.writeBytes(elf)
        val report = FormatStaticAnalyzer.analyze(file)
        assertTrue(report.supported)
        assertTrue(report.evidence.any { it.code == "ELF_FORMAT_IDENTIFIED" })
        assertTrue(report.evidence.any { it.code == "ELF_EXECVE_SYMBOL" })
    }

    @Test
    fun unsupportedTextIsNotMarkedAsStructurallyCovered() {
        val file = temporary.newFile("note.txt")
        file.writeText("ordinary text")
        val report = FormatStaticAnalyzer.analyze(file)
        assertFalse(report.supported)
        assertTrue(report.complete)
    }

    private fun zip(name: String, vararg entries: Pair<String, ByteArray>): File {
        val file = temporary.newFile(name)
        ZipOutputStream(file.outputStream()).use { output ->
            entries.forEach { (entryName, bytes) ->
                output.putNextEntry(ZipEntry(entryName))
                output.write(bytes)
                output.closeEntry()
            }
        }
        return file
    }
}

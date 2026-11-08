package com.antivirusalai.engine

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class InstalledPackageArchiveCollectorTest {
    @get:Rule
    val temporary = TemporaryFolder()

    @Test
    fun countsUnreadableSplitEvenWhenBaseApkIsReadable() {
        val base = temporary.newFile("base.apk").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val missingSplit = File(temporary.root, "split_config.arm64_v8a.apk")
        val output = linkedMapOf<String, File>()

        val result = InstalledPackageArchiveCollector.collect(
            listOf(base.absolutePath, missingSplit.absolutePath),
            output,
            maxFiles = 10
        )

        assertEquals(1, result.addedComponents)
        assertEquals(1, result.skippedComponents)
        assertEquals(1, output.size)
    }

    @Test
    fun countsMissingBasePathInsteadOfDroppingIt() {
        val output = linkedMapOf<String, File>()

        val result = InstalledPackageArchiveCollector.collect(
            listOf(null, " "),
            output,
            maxFiles = 10
        )

        assertEquals(0, result.addedComponents)
        assertEquals(2, result.skippedComponents)
        assertEquals(0, output.size)
    }

    @Test
    fun deduplicatesTheSameReadableComponentAcrossPackages() {
        val apk = temporary.newFile("shared.apk").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val output = linkedMapOf<String, File>()

        val first = InstalledPackageArchiveCollector.collect(
            listOf(apk.absolutePath),
            output,
            maxFiles = 10
        )
        val second = InstalledPackageArchiveCollector.collect(
            listOf(apk.absolutePath),
            output,
            maxFiles = 10
        )

        assertEquals(1, first.addedComponents)
        assertEquals(0, first.skippedComponents)
        assertEquals(0, second.addedComponents)
        assertEquals(0, second.skippedComponents)
        assertEquals(1, output.size)
    }

    @Test
    fun stopsAtTheCandidateLimitWithoutMiscountingUnvisitedComponents() {
        val first = temporary.newFile("base.apk").apply { writeBytes(byteArrayOf(1)) }
        val output = linkedMapOf<String, File>()

        val result = InstalledPackageArchiveCollector.collect(
            listOf(first.absolutePath, null, "unvisited.apk"),
            output,
            maxFiles = 1
        )

        assertEquals(1, result.addedComponents)
        assertEquals(0, result.skippedComponents)
        assertEquals(1, output.size)
    }
}

package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanCoverageTest {
    @Test
    fun separatesScannedCoverageFromExplicitlyAccountedFiles() {
        val report = FolderScanReport(
            items = emptyList(),
            failures = emptyList(),
            discoveredFiles = 10,
            skippedFiles = 3,
            truncated = false,
            scannedCountOverride = 7
        )

        assertEquals(7, report.scannedCount)
        assertEquals(70, report.scanCoveragePercent)
        assertEquals(0, report.unaccountedFiles)
        assertTrue(report.allDiscoveredFilesAccounted)
        assertFalse(report.fullScanCoverage)
    }

    @Test
    fun exposesAnyCandidateWithoutATerminalDisposition() {
        val report = FolderScanReport(
            items = emptyList(),
            failures = emptyList(),
            discoveredFiles = 10,
            skippedFiles = 2,
            truncated = true,
            scannedCountOverride = 4
        )

        assertEquals(40, report.scanCoveragePercent)
        assertEquals(4, report.unaccountedFiles)
        assertFalse(report.allDiscoveredFilesAccounted)
        assertFalse(report.fullScanCoverage)
    }

    @Test
    fun emptySuccessfulScopeHasFullCoverageButUnavailableScopeDoesNot() {
        val empty = FolderScanReport(emptyList(), emptyList(), 0, 0, false)
        val unavailable = FolderScanReport(
            emptyList(),
            listOf(FolderScanFailure("Shared storage", "Permission not granted")),
            0,
            0,
            true
        )

        assertEquals(100, empty.scanCoveragePercent)
        assertTrue(empty.fullScanCoverage)
        assertEquals(0, unavailable.scanCoveragePercent)
        assertFalse(unavailable.fullScanCoverage)
    }
}

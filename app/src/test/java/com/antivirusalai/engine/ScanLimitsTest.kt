package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanLimitsTest {
    @Test
    fun deepDeviceAndFolderScansSupportLibrariesLargerThanSixtyThousandFiles() {
        assertTrue(ScanLimits.DEEP_FILE_LIMIT >= 60_000)
        assertTrue(ScanLimits.FOLDER_FILE_LIMIT >= 60_000)
    }

    @Test
    fun deepAndFolderBudgetsAreExplicitAndBounded() {
        assertTrue(ScanLimits.DEEP_TOTAL_BYTES >= 20L * 1024L * 1024L * 1024L)
        assertTrue(ScanLimits.FOLDER_TOTAL_BYTES >= 20L * 1024L * 1024L * 1024L)
        assertTrue(ScanLimits.DEEP_FILE_LIMIT < Int.MAX_VALUE)
    }

    @Test
    fun reportCountersCanRepresentAllScannedFilesWhenOnlyPreviewItemsAreKept() {
        val report = FolderScanReport(
            items = emptyList(),
            failures = emptyList(),
            discoveredFiles = 60_000,
            skippedFiles = 0,
            truncated = false,
            scannedCountOverride = 60_000,
            suspiciousCountOverride = 12,
            unknownCountOverride = 59_000,
            matchedCountOverride = 1
        )

        assertEquals(60_000, report.scannedCount)
        assertEquals(12, report.suspiciousCount)
        assertEquals(59_000, report.unknownCount)
        assertEquals(1, report.matchedCount)
    }
}

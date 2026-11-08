package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UnknownFileInvestigatorTest {
    private fun result(
        verdict: ScanVerdict,
        hash: String = "a".repeat(64),
        name: String = "private-document.pdf"
    ) = ScanResult(
        displayName = name,
        mimeType = "application/pdf",
        sizeBytes = 1024,
        sha256 = hash,
        verdict = verdict,
        evidence = listOf(ScanEvidence("FORMAT_NOT_SUPPORTED", "Unsupported", "Details", EvidenceSeverity.INFO)),
        apkMetadata = null,
        durationMillis = 1,
        staticAnalysis = StaticAnalysisSummary("PDF", false, false, 0, 0, emptySet())
    )

    @Test
    fun unknownAndIncompleteFilesEnterInvestigation() {
        assertTrue(UnknownFileInvestigator.shouldInvestigate(ScanVerdict.UNKNOWN_APK))
        assertTrue(UnknownFileInvestigator.shouldInvestigate(ScanVerdict.UNSUPPORTED_FILE))
        assertTrue(UnknownFileInvestigator.shouldInvestigate(ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE))
        assertNotNull(UnknownFileInvestigator.createCase(result(ScanVerdict.UNSUPPORTED_FILE), 123L))
    }

    @Test
    fun confirmedVerdictsDoNotEnterUnknownQueue() {
        assertFalse(UnknownFileInvestigator.shouldInvestigate(ScanVerdict.KNOWN_MALWARE))
        assertFalse(UnknownFileInvestigator.shouldInvestigate(ScanVerdict.NO_KNOWN_INDICATOR))
        assertNull(UnknownFileInvestigator.createCase(result(ScanVerdict.SUSPICIOUS)))
    }

    @Test
    fun invalidHashIsRejectedAndCaseContainsNoFilenameOrFileBytes() {
        assertNull(UnknownFileInvestigator.createCase(result(ScanVerdict.UNSUPPORTED_FILE, "not-a-sha256")))
        val item = UnknownFileInvestigator.createCase(result(ScanVerdict.UNSUPPORTED_FILE), 123L)
        assertNotNull(item)
        assertEquals("a".repeat(64), item!!.sha256)
        assertEquals(UnknownFileCase.REMOTE_LOOKUP_NOT_CONFIGURED, item.remoteLookupState)
        assertTrue(item.evidenceCodes.contains("FORMAT_NOT_SUPPORTED"))
        assertFalse(item.toString().contains("private-document.pdf"))
    }
}

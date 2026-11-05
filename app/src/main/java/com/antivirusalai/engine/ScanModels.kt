package com.antivirusalai.engine

enum class ScanVerdict {
    TEST_MARKER_MATCH,
    SUSPICIOUS,
    NO_KNOWN_INDICATOR,
    UNKNOWN_APK,
    UNSUPPORTED_FILE,
    CODE_ANALYZED,
    CODE_ISSUES_FOUND,
    CODE_ANALYSIS_LIMITED
}
enum class EvidenceSeverity { INFO, LOW, MEDIUM, HIGH }

data class ScanEvidence(
    val code: String,
    val title: String,
    val detail: String,
    val severity: EvidenceSeverity
)

data class ApkMetadata(
    val packageName: String,
    val versionName: String?,
    val targetSdk: Int,
    val requestedPermissions: Set<String>,
    val debuggable: Boolean,
    val signingCertificateSha256: String?,
    val exportedComponentCount: Int,
    val declaredAccessibilityServiceCount: Int
)

data class PermissionAssessment(
    val score: Int,
    val suspicious: Boolean,
    val evidence: List<ScanEvidence>
)

data class ScanResult(
    val displayName: String,
    val mimeType: String?,
    val sizeBytes: Long,
    val sha256: String,
    val verdict: ScanVerdict,
    val evidence: List<ScanEvidence>,
    val apkMetadata: ApkMetadata?,
    val durationMillis: Long,
    val codeAnalysis: CodeAnalysisReport? = null
)

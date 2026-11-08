package com.antivirusalai.engine

enum class ScanVerdict { KNOWN_MALWARE, POTENTIALLY_UNWANTED, TEST_MARKER_MATCH, SUSPICIOUS, NO_KNOWN_INDICATOR, UNKNOWN_APK, UNSUPPORTED_FILE, INCOMPLETE_THREAT_INTELLIGENCE }
enum class EvidenceSeverity { INFO, LOW, MEDIUM, HIGH }
enum class ContentEngineState { UNAVAILABLE, INCOMPLETE, COMPLETE }
enum class MlModelState { NOT_CONFIGURED, READY, ERROR }
enum class BehavioralAnalysisState { NOT_APPLICABLE, STATIC_INDICATORS_ONLY, SANDBOX_NOT_CONFIGURED }

data class ContentSignatureRule(
    val id: String,
    val familyId: String,
    val classification: com.antivirusalai.intel.ThreatClassification,
    val confidence: Int,
    val pattern: ByteArray,
    val description: String,
    val sourceId: String = "INTERNAL",
    val licenseId: String = "UNSPECIFIED"
)

data class StaticAnalysisSummary(
    val format: String?,
    val supported: Boolean,
    val complete: Boolean,
    val entryCount: Int,
    val expandedBytes: Long,
    val signalCategories: Set<String>
)

data class MlFeatureVector(
    val featureCount: Int,
    val values: Map<String, Float>
)

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
    val contentEngineState: ContentEngineState = ContentEngineState.UNAVAILABLE,
    val contentRuleSetId: String? = null,
    val contentRuleMatches: List<String> = emptyList(),
    val contentEngineErrorCode: String? = null,
    val contentRuleBundleVersion: Long? = null,
    val staticAnalysis: StaticAnalysisSummary? = null,
    val mlModelState: MlModelState = MlModelState.NOT_CONFIGURED,
    val mlFeatureCount: Int = 0,
    val behavioralAnalysisState: BehavioralAnalysisState = BehavioralAnalysisState.NOT_APPLICABLE
)

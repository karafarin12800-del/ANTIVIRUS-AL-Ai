package com.antivirusalai.engine

data class CombinedRiskAssessment(
    val score: Int,
    val suspicious: Boolean,
    val evidence: List<ScanEvidence>,
    val independentSignalGroups: Set<String>
)

object MultiSignalRiskScorer {
    fun assess(permission: PermissionAssessment?, static: StaticAnalysisReport): CombinedRiskAssessment {
        val evidence = mutableListOf<ScanEvidence>()
        if (permission != null) evidence += permission.evidence
        evidence += static.evidence
        val groups = linkedSetOf<String>()
        if ((permission?.score ?: 0) >= 3) groups += "MANIFEST_CAPABILITIES"
        if (static.signalCategories.any { it in setOf("SENSITIVE_API", "INSTALL_API", "ACCESSIBILITY", "DEVICE_ADMIN") }) {
            groups += "DEX_CAPABILITIES"
        }
        if (static.signalCategories.any { it in setOf("PROCESS_EXECUTION", "NATIVE_EXECUTION", "NATIVE_INSPECTION", "DYNAMIC_CODE") }) {
            groups += "CODE_EXECUTION_OR_LOADING"
        }
        if (static.signalCategories.any { it in setOf("ARCHIVE_ANOMALY", "FORMAT_ANOMALY") }) {
            groups += "FORMAT_OR_ARCHIVE_ANOMALY"
        }
        val score = ((permission?.score ?: 0) + static.riskPoints).coerceAtMost(100)
        val multiSignal = groups.size >= 2 && score >= 8
        if (multiSignal) {
            evidence += ScanEvidence(
                "INDEPENDENT_MULTI_SIGNAL_HEURISTIC",
                "Multiple independent risk indicators",
                "The file has signals from ${groups.size} independent analysis groups. This is a review-level heuristic, not a confirmed malware signature.",
                EvidenceSeverity.MEDIUM
            )
        }
        return CombinedRiskAssessment(
            score,
            permission?.suspicious == true || multiSignal,
            evidence,
            groups
        )
    }
}

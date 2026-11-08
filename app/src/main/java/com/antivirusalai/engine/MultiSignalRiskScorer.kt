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

/** Feature extraction is ready; inference remains disabled until a licensed,
 * labelled dataset and independently validated model are supplied. */
object OnDeviceMlScorer {
    fun extractFeatures(
        apk: ApkMetadata?,
        static: StaticAnalysisReport,
        combined: CombinedRiskAssessment
    ): MlFeatureVector {
        val values = linkedMapOf<String, Float>()
        values["permission_count"] = (apk?.requestedPermissions?.size ?: 0).toFloat()
        values["debuggable"] = if (apk?.debuggable == true) 1f else 0f
        values["exported_components"] = (apk?.exportedComponentCount ?: 0).toFloat()
        values["static_signal_categories"] = static.signalCategories.size.toFloat()
        values["archive_entries"] = static.entryCount.toFloat()
        values["archive_expanded_mib"] = static.expandedBytes.toFloat() / (1024f * 1024f)
        values["independent_signal_groups"] = combined.independentSignalGroups.size.toFloat()
        values["static_analysis_complete"] = if (static.complete) 1f else 0f
        return MlFeatureVector(values.size, values)
    }

    fun score(@Suppress("UNUSED_PARAMETER") features: MlFeatureVector): MlModelState =
        MlModelState.NOT_CONFIGURED
}

package com.antivirusalai.engine

/**
 * Conservative manifest heuristics. A permission or metadata signal is not proof
 * that an app is malicious; findings are evidence for human review.
 */
object PermissionRiskAnalyzer {
    private const val SMS_SEND = "android.permission.SEND_SMS"
    private const val SMS_READ = "android.permission.READ_SMS"
    private const val SMS_RECEIVE = "android.permission.RECEIVE_SMS"
    private const val INSTALL_PACKAGES = "android.permission.REQUEST_INSTALL_PACKAGES"
    private const val OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW"

    fun analyze(apk: ApkMetadata): PermissionAssessment {
        val p = apk.requestedPermissions
        val evidence = mutableListOf<ScanEvidence>()
        var score = 0

        val sms = setOf(SMS_SEND, SMS_READ, SMS_RECEIVE)
        if (p.containsAll(sms)) {
            score += 5
            evidence += ScanEvidence(
                "SMS_PERMISSION_COMBINATION",
                "Combined SMS capabilities",
                "The APK requests SMS send, read, and receive permissions together. This needs contextual review; it is not proof of malware.",
                EvidenceSeverity.HIGH
            )
        } else if (p.any { it in sms }) {
            evidence += ScanEvidence(
                "SENSITIVE_SMS_PERMISSION",
                "Sensitive SMS permission",
                "At least one SMS permission is requested. Legitimate apps may use SMS features; inspect the app's purpose and publisher.",
                EvidenceSeverity.LOW
            )
        }

        if (INSTALL_PACKAGES in p && OVERLAY in p) {
            score += 4
            evidence += ScanEvidence(
                "INSTALL_AND_OVERLAY_COMBINATION",
                "Install and overlay capability combination",
                "The APK requests package-install and screen-overlay capabilities together. This combination deserves manual review.",
                EvidenceSeverity.MEDIUM
            )
        }

        if (apk.declaredAccessibilityServiceCount > 0) {
            evidence += ScanEvidence(
                "ACCESSIBILITY_SERVICE_PERMISSION",
                "Accessibility service declaration",
                "The APK declares ${apk.declaredAccessibilityServiceCount} accessibility service(s). Accessibility services can be legitimate but are security-sensitive.",
                EvidenceSeverity.MEDIUM
            )
        }

        if (apk.debuggable) {
            score += 1
            evidence += ScanEvidence(
                "DEBUGGABLE_BUILD",
                "Debuggable APK",
                "The APK allows debugging. This is common in test builds and should be reviewed before production use.",
                EvidenceSeverity.LOW
            )
        }

        if (apk.targetSdk in 1..27) {
            score += 1
            evidence += ScanEvidence(
                "OLD_TARGET_SDK",
                "Old target SDK",
                "The APK targets an old Android API level. This can indicate outdated security behavior, but does not establish malicious intent.",
                EvidenceSeverity.LOW
            )
        }

        if (apk.signingCertificateSha256 == null) {
            evidence += ScanEvidence(
                "SIGNER_UNAVAILABLE",
                "Signing certificate unavailable",
                "The package parser did not expose a signer certificate. Signature authenticity could not be assessed.",
                EvidenceSeverity.MEDIUM
            )
        }

        if (apk.exportedComponentCount > 0) {
            evidence += ScanEvidence(
                "EXPORTED_COMPONENTS",
                "Exported Android components",
                "${apk.exportedComponentCount} component(s) are exported. This can be intentional; access controls need deeper review.",
                EvidenceSeverity.INFO
            )
        }

        if (evidence.isEmpty()) {
            evidence += ScanEvidence(
                "NO_HEURISTIC_SIGNAL",
                "No configured heuristic matched",
                "No high-signal rule in this small MVP rule set matched the APK metadata. This does not prove the app is safe.",
                EvidenceSeverity.INFO
            )
        }

        return PermissionAssessment(score, score >= 4, evidence)
    }
}

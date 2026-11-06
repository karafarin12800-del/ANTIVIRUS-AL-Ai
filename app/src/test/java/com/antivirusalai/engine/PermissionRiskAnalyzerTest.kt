package com.antivirusalai.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PermissionRiskAnalyzerTest {
    private fun apk(permissions: Set<String>, accessibilityServices: Int = 0) = ApkMetadata(
        packageName = "example.test",
        versionName = "1.0",
        targetSdk = 35,
        requestedPermissions = permissions,
        debuggable = false,
        signingCertificateSha256 = "a".repeat(64),
        exportedComponentCount = 0,
        declaredAccessibilityServiceCount = accessibilityServices
    )

    @Test
    fun oneSensitivePermissionDoesNotDeclareApkSuspicious() {
        val assessment = PermissionRiskAnalyzer.analyze(
            apk(setOf("android.permission.SEND_SMS"))
        )
        assertFalse(assessment.suspicious)
    }

    @Test
    fun oneCapabilityClusterProducesEvidenceButDoesNotTriggerSuspiciousVerdict() {
        val assessment = PermissionRiskAnalyzer.analyze(
            apk(
                setOf(
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                    "android.permission.SYSTEM_ALERT_WINDOW"
                )
            )
        )
        assertTrue(assessment.evidence.any { it.code == "INSTALL_AND_OVERLAY_COMBINATION" })
        assertFalse(assessment.suspicious)
    }

    @Test
    fun independentHighRiskCapabilityClustersTriggerReviewVerdict() {
        val assessment = PermissionRiskAnalyzer.analyze(
            apk(
                setOf(
                    "android.permission.SEND_SMS",
                    "android.permission.READ_SMS",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                    "android.permission.SYSTEM_ALERT_WINDOW"
                )
            )
        )
        assertTrue(assessment.suspicious)
    }

    @Test
    fun accessibilityServiceDeclarationIsReportedFromServiceMetadata() {
        val assessment = PermissionRiskAnalyzer.analyze(
            apk(emptySet(), accessibilityServices = 1)
        )
        assertTrue(assessment.evidence.any { it.code == "ACCESSIBILITY_SERVICE_PERMISSION" })
        assertFalse(assessment.suspicious)
    }

    @Test
    fun exportedComponentsAreInformationalOnly() {
        val assessment = PermissionRiskAnalyzer.analyze(
            apk(emptySet()).copy(exportedComponentCount = 3)
        )
        assertFalse(assessment.suspicious)
    }
}

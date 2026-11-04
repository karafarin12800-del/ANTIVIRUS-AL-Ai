package com.antivirusalai.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PermissionRiskAnalyzerTest {
    private fun apk(permissions: Set<String>) = ApkMetadata(
        packageName = "example.test",
        versionName = "1.0",
        targetSdk = 35,
        requestedPermissions = permissions,
        debuggable = false,
        signingCertificateSha256 = "a".repeat(64),
        exportedComponentCount = 0
    )

    @Test
    fun oneSensitivePermissionDoesNotDeclareApkSuspicious() {
        val assessment = PermissionRiskAnalyzer.analyze(
            apk(setOf("android.permission.SEND_SMS"))
        )
        assertFalse(assessment.suspicious)
    }

    @Test
    fun installAndOverlayCombinationIsFlaggedForReview() {
        val assessment = PermissionRiskAnalyzer.analyze(
            apk(
                setOf(
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                    "android.permission.SYSTEM_ALERT_WINDOW"
                )
            )
        )
        assertTrue(assessment.suspicious)
    }

    @Test
    fun exportedComponentsAreInformationalOnly() {
        val assessment = PermissionRiskAnalyzer.analyze(
            apk(emptySet()).copy(exportedComponentCount = 3)
        )
        assertFalse(assessment.suspicious)
    }
}

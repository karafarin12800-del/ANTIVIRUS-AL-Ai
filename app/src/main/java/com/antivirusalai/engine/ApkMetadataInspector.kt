package com.antivirusalai.engine

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

/**
 * Reads package metadata only. It never installs, loads, or executes the APK.
 */
object ApkMetadataInspector {
    fun inspect(context: Context, apkFile: File): ApkMetadata? {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or
            PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_PROVIDERS

        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageArchiveInfo(
                apkFile.absolutePath,
                flags or PackageManager.GET_SIGNING_CERTIFICATES
            )
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageArchiveInfo(
                apkFile.absolutePath,
                flags or PackageManager.GET_SIGNATURES
            )
        } ?: return null

        val appInfo = info.applicationInfo
        appInfo?.sourceDir = apkFile.absolutePath
        appInfo?.publicSourceDir = apkFile.absolutePath

        val signerBytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
        } else {
            @Suppress("DEPRECATION")
            info.signatures?.firstOrNull()?.toByteArray()
        }
        val signerHash = signerBytes?.let { bytes ->
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
                "%02x".format(it.toInt() and 0xff)
            }
        }

        val accessibilityServiceCount = info.services.orEmpty().count {
            it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
        }

        val exportedCount =
            info.activities.orEmpty().count { it.exported } +
            info.services.orEmpty().count { it.exported } +
            info.receivers.orEmpty().count { it.exported } +
            info.providers.orEmpty().count { it.exported }

        val appFlags = appInfo?.flags ?: 0
        return ApkMetadata(
            packageName = info.packageName,
            versionName = info.versionName,
            targetSdk = appInfo?.targetSdkVersion ?: 0,
            requestedPermissions = info.requestedPermissions?.toSet().orEmpty(),
            debuggable = (appFlags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
            signingCertificateSha256 = signerHash,
            exportedComponentCount = exportedCount,
            declaredAccessibilityServiceCount = accessibilityServiceCount
        )
    }
}

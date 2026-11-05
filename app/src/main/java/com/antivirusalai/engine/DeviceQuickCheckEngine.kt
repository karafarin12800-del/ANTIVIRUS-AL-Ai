package com.antivirusalai.engine

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class DeviceAppFinding(val packageName: String, val riskIndicators: List<String>)

data class DeviceQuickCheckReport(
    val checkedApps: Int,
    val appsWithIndicators: List<DeviceAppFinding>,
    val permissionInventoryAvailable: Boolean,
    val coverageNote: String
) {
    val hasIndicators: Boolean get() = appsWithIndicators.isNotEmpty()
}

/** Package inventory only: Android visibility limits apply; this is not a malware verdict. */
object DeviceQuickCheckEngine {
    private val sensitivePermissions = setOf(
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS", "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG", "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS", "android.permission.READ_PHONE_STATE",
        "android.permission.ACCESS_FINE_LOCATION"
    )

    suspend fun run(context: Context): DeviceQuickCheckReport = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val apps = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0)
        }
        val findings = mutableListOf<DeviceAppFinding>()
        var inspected = 0
        apps.forEach { app ->
            if (app.packageName == context.packageName) return@forEach
            val info = try { getPackageInfo(pm, app.packageName) }
                catch (_: PackageManager.NameNotFoundException) { null }
                catch (_: SecurityException) { null }
                ?: return@forEach
            inspected++
            val permissions = info.requestedPermissions.orEmpty().toSet()
            val matched = permissions.intersect(sensitivePermissions)
            val indicators = buildList {
                if (matched.size >= 3) add("Multiple sensitive permissions (3 or more)")
                if ("android.permission.REQUEST_INSTALL_PACKAGES" in matched) add("Can request package installation")
                if ("android.permission.SYSTEM_ALERT_WINDOW" in matched) add("Can request display-over-other-apps access")
                if ((("android.permission.READ_SMS" in matched) || ("android.permission.RECEIVE_SMS" in matched)) &&
                    "android.permission.SEND_SMS" in matched) add("SMS read/receive and send permissions")
            }.distinct()
            if (indicators.isNotEmpty()) findings += DeviceAppFinding(app.packageName, indicators)
        }
        DeviceQuickCheckReport(
            checkedApps = inspected,
            appsWithIndicators = findings.sortedByDescending { it.riskIndicators.size },
            permissionInventoryAvailable = inspected > 0,
            coverageNote = "Only packages visible under Android package-visibility rules were inspected. App-private data and runtime behavior were not scanned."
        )
    }

    @Suppress("DEPRECATION")
    private fun getPackageInfo(pm: PackageManager, packageName: String): PackageInfo =
        if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(
            packageName,
            PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
        ) else pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
}

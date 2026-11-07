package com.antivirusalai

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.antivirusalai.engine.ScanEngine
import com.antivirusalai.engine.ScanVerdict
import kotlinx.coroutines.CancellationException
import java.io.File

/**
 * Watches package installation and replacement events, then inspects the newly
 * installed APK locally. Android does not permit a third-party app to block
 * installation or inspect another app's private runtime memory.
 */
object PackageProtectionSettings {
    private const val PREFS = "package-protection"
    private const val ENABLED = "enabled"

    fun isEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(ENABLED, true)

    fun setEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(ENABLED, enabled).apply()
    }

    fun record(
        context: Context,
        packageName: String,
        appLabel: String,
        verdict: String,
        detail: String
    ) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("last_package", packageName)
            .putString("last_label", appLabel)
            .putString("last_verdict", verdict)
            .putString("last_detail", detail.take(500))
            .putLong("last_checked_at", System.currentTimeMillis())
            .apply()
    }
}

class PackageInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action != Intent.ACTION_PACKAGE_ADDED &&
            action != Intent.ACTION_PACKAGE_REPLACED
        ) return

        // PACKAGE_REPLACED is the single update event; avoid scheduling twice.
        if (action == Intent.ACTION_PACKAGE_ADDED &&
            intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
        ) return

        if (!PackageProtectionSettings.isEnabled(context)) return
        val packageName = intent.data?.schemeSpecificPart
            ?.takeIf { it.isNotBlank() && it != context.packageName } ?: return

        val request = OneTimeWorkRequestBuilder<PackageInstallProtectionWorker>()
            .setInputData(workDataOf(PackageInstallProtectionWorker.KEY_PACKAGE_NAME to packageName))
            .build()

        WorkManager.getInstance(context.applicationContext).enqueueUniqueWork(
            "alai-package-install-$packageName",
            ExistingWorkPolicy.REPLACE,
            request
        )
    }
}

class PackageInstallProtectionWorker(
    appContext: Context,
    parameters: WorkerParameters
) : CoroutineWorker(appContext, parameters) {
    override suspend fun doWork(): Result {
        if (!PackageProtectionSettings.isEnabled(applicationContext)) return Result.success()
        val packageName = inputData.getString(KEY_PACKAGE_NAME)
            ?.takeIf { it.isNotBlank() } ?: return Result.failure()

        return try {
            val appInfo = getApplicationInfo(packageName) ?: return Result.success()
            val label = runCatching {
                applicationContext.packageManager.getApplicationLabel(appInfo).toString()
            }.getOrDefault(packageName)

            val paths = (listOfNotNull(appInfo.sourceDir) + appInfo.splitSourceDirs.orEmpty())
                .distinct()
            if (paths.isEmpty()) {
                recordUnknown(packageName, label, "Android did not expose an APK path for this package.")
                return Result.success()
            }

            var status = STATUS_NO_KNOWN_INDICATOR
            val details = mutableListOf<String>()
            for (path in paths) {
                if (!PackageProtectionSettings.isEnabled(applicationContext)) return Result.success()
                val apk = File(path)
                if (!apk.isFile || !apk.canRead()) {
                    status = stronger(status, STATUS_UNKNOWN)
                    details += "An installed APK component was not readable."
                    continue
                }
                try {
                    val result = ScanEngine.scan(applicationContext, Uri.fromFile(apk))
                    when (result.verdict) {
                        ScanVerdict.KNOWN_MALWARE -> {
                            status = STATUS_MALWARE
                            details += result.evidence.firstOrNull()?.detail ?: "Known malware hash match."
                        }
                        ScanVerdict.POTENTIALLY_UNWANTED -> {
                            status = stronger(status, STATUS_PUA)
                            details += result.evidence.firstOrNull()?.detail ?: "Potentially unwanted application."
                        }
                        ScanVerdict.SUSPICIOUS -> {
                            status = stronger(status, STATUS_SUSPICIOUS)
                            details += result.evidence.firstOrNull()?.detail ?: "Suspicious APK indicators."
                        }
                        ScanVerdict.UNKNOWN_APK, ScanVerdict.UNSUPPORTED_FILE -> {
                            status = stronger(status, STATUS_UNKNOWN)
                            details += result.evidence.firstOrNull()?.detail ?: "The APK could not be fully assessed."
                        }
                        ScanVerdict.NO_KNOWN_INDICATOR -> Unit
                        ScanVerdict.TEST_MARKER_MATCH -> Unit
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    status = stronger(status, STATUS_UNKNOWN)
                    details += error.message ?: "An APK component could not be checked."
                }
            }

            val detail = details.distinct().joinToString(" ").ifBlank {
                "No known indicator was found by the available local hash and APK-permission checks. This is not proof that the app is harmless."
            }
            PackageProtectionSettings.record(applicationContext, packageName, label, status, detail)
            if (status == STATUS_MALWARE || status == STATUS_PUA || status == STATUS_SUSPICIOUS) {
                notifyFinding(label, status, detail)
            }
            Result.success()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            PackageProtectionSettings.record(
                applicationContext, packageName, packageName, STATUS_UNKNOWN,
                error.message ?: "The installed application could not be checked."
            )
            Result.success()
        }
    }

    private fun getApplicationInfo(packageName: String): ApplicationInfo? =
        try {
            val pm = applicationContext.packageManager
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(packageName, 0)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            null
        }

    private fun recordUnknown(packageName: String, label: String, detail: String) {
        PackageProtectionSettings.record(applicationContext, packageName, label, STATUS_UNKNOWN, detail)
    }

    private fun stronger(current: String, candidate: String): String {
        val priority = mapOf(
            STATUS_NO_KNOWN_INDICATOR to 0,
            STATUS_UNKNOWN to 1,
            STATUS_PUA to 2,
            STATUS_SUSPICIOUS to 3,
            STATUS_MALWARE to 4
        )
        return if ((priority[candidate] ?: 0) > (priority[current] ?: 0)) candidate else current
    }

    private fun notifyFinding(label: String, status: String, detail: String) {
        if (Build.VERSION.SDK_INT >= 33 &&
            applicationContext.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) return

        val manager = applicationContext.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "App install protection", NotificationManager.IMPORTANCE_HIGH)
                .apply {
                    description = "Alerts when a newly installed or updated app has a known or suspicious indicator."
                }
        )
        val title = when (status) {
            STATUS_MALWARE -> "ANTIVIRUS AL AI · Threat detected"
            STATUS_PUA -> "ANTIVIRUS AL AI · App needs review"
            else -> "ANTIVIRUS AL AI · Suspicious app"
        }
        val body = when (status) {
            STATUS_MALWARE -> "$label matched a known malware hash. Review and uninstall it in Android settings."
            STATUS_PUA -> "$label matched a potentially unwanted app indicator. Review it before use."
            else -> "$label has suspicious APK indicators. Review the app and its permissions."
        }
        val notification = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$body\n$detail"))
            .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        runCatching { manager.notify(NOTIFICATION_ID, notification) }
    }

    companion object {
        const val KEY_PACKAGE_NAME = "package_name"
        const val STATUS_NO_KNOWN_INDICATOR = "NO_KNOWN_INDICATOR"
        const val STATUS_UNKNOWN = "UNKNOWN"
        const val STATUS_PUA = "POTENTIALLY_UNWANTED"
        const val STATUS_SUSPICIOUS = "SUSPICIOUS"
        const val STATUS_MALWARE = "KNOWN_MALWARE"
        private const val CHANNEL_ID = "alai-app-install-protection"
        private const val NOTIFICATION_ID = 4201
    }
}

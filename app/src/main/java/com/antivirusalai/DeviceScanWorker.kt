package com.antivirusalai

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.antivirusalai.engine.DeviceScanEngine
import com.antivirusalai.engine.ScanReportStore

class DeviceScanWorker(appContext: Context, parameters: WorkerParameters) : CoroutineWorker(appContext, parameters) {
    override suspend fun doWork(): Result {
        val deep = inputData.getBoolean(KEY_DEEP, false)
        val startedAt = inputData.getLong(KEY_STARTED_AT_MS, System.currentTimeMillis())
        ScanRuntime.isActive = true
        return try {
            setProgress(workDataOf(
                KEY_DEEP to deep,
                KEY_STARTED_AT_MS to startedAt,
                KEY_CURRENT to 0,
                KEY_TOTAL to 0
            ))
            setForeground(createForegroundInfo(0, 0))
            val report = DeviceScanEngine.scanDevice(applicationContext, deep) { current, total, name ->
                val elapsed = (System.currentTimeMillis() - startedAt).coerceAtLeast(0L)
                setProgress(workDataOf(
                    KEY_DEEP to deep,
                    KEY_STARTED_AT_MS to startedAt,
                    KEY_CURRENT to current,
                    KEY_TOTAL to total,
                    KEY_CURRENT_NAME to "$current / $total • $name",
                    KEY_ELAPSED_MS to elapsed
                ))
                setForeground(createForegroundInfo(current, total))
            }
            ScanReportStore.save(applicationContext, deep, report)
            Result.success(workDataOf(
                KEY_DEEP to deep,
                KEY_STARTED_AT_MS to startedAt,
                KEY_CURRENT to report.scannedCount,
                KEY_TOTAL to report.discoveredFiles,
                KEY_ELAPSED_MS to (System.currentTimeMillis() - startedAt).coerceAtLeast(0L)
            ))
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            Result.failure(workDataOf(
                KEY_DEEP to deep,
                KEY_STARTED_AT_MS to startedAt,
                KEY_ERROR to (error.message ?: "Device scan failed.")
            ))
        } finally {
            ScanRuntime.isActive = false
        }
    }

    private fun createForegroundInfo(current: Int, total: Int): ForegroundInfo {
        createNotificationChannel()
        val notification = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle("ANTIVIRUS AL AI · Scan")
            .setContentText(if (total > 0) "Checking accessible files · $current / $total" else "Preparing the device scan")
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true).setOnlyAlertOnce(true).setSilent(true)
            .setProgress(total.coerceAtLeast(0), current.coerceAtLeast(0), total <= 0)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Cancel scan",
                WorkManager.getInstance(applicationContext).createCancelPendingIntent(id))
            .build()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ForegroundInfo(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else ForegroundInfo(NOTIFICATION_ID, notification)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = applicationContext.getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(
                CHANNEL_ID, "Device scan", NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows progress while ANTIVIRUS AL AI scans accessible device files."
                setShowBadge(false)
            })
        }
    }

    companion object {
        const val WORK_NAME = "alai-device-scan"
        const val KEY_DEEP = "device_scan_deep"
        const val KEY_STARTED_AT_MS = "device_scan_started_at_ms"
        const val KEY_CURRENT = "device_scan_current"
        const val KEY_TOTAL = "device_scan_total"
        const val KEY_CURRENT_NAME = "device_scan_current_name"
        const val KEY_ELAPSED_MS = "device_scan_elapsed_ms"
        const val KEY_ERROR = "device_scan_error"
        private const val CHANNEL_ID = "alai-device-scan"
        private const val NOTIFICATION_ID = 4107
    }
}

object ScanRuntime {
    @Volatile var isActive: Boolean = false
}

package com.antivirusalai.intel

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Background refresh of signed intelligence only.
 * It is not a real-time file, process, or network monitor.
 */
class ThreatFeedRefreshWorker(
    appContext: Context,
    parameters: WorkerParameters
) : CoroutineWorker(appContext, parameters) {
    override suspend fun doWork(): Result =
        try {
            val feed = ThreatFeedRuntime.refresh(applicationContext)
            applicationContext.getSharedPreferences("threat-feed-status", Context.MODE_PRIVATE)
                .edit()
                .putLong("version", feed.version)
                .putInt("indicator_count", feed.indicators.size)
                .putLong("expires_at", feed.expiresAtEpochSeconds)
                .putLong("updated_at", System.currentTimeMillis())
                .apply()
            Result.success()
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            Result.retry()
        }
}

object ThreatFeedScheduler {
    private const val PERIODIC_NAME = "alai-signed-feed-periodic-refresh"
    private const val FIRST_RUN_NAME = "alai-signed-feed-first-refresh"

    fun schedule(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .setRequiresBatteryNotLow(true)
            .build()

        val periodic = PeriodicWorkRequestBuilder<ThreatFeedRefreshWorker>(
            12, TimeUnit.HOURS
        )
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()

        // First refresh should not wait for the battery-not-low condition.
        // A network connection is sufficient; WorkManager still applies its own
        // execution and quota policies.
        val firstRunConstraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val firstRun = OneTimeWorkRequestBuilder<ThreatFeedRefreshWorker>()
            .setConstraints(firstRunConstraints)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
            .build()

        WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
            PERIODIC_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            periodic
        )
        WorkManager.getInstance(context.applicationContext).enqueueUniqueWork(
            FIRST_RUN_NAME,
            ExistingWorkPolicy.KEEP,
            firstRun
        )
    }
}

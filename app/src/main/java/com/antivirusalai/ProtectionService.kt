package com.antivirusalai

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.antivirusalai.engine.ScanEngine
import com.antivirusalai.engine.ScanVerdict
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList

/**
 * User-enabled, visible protection monitor.
 *
 * It watches accessible shared-storage folders for completed writes/moves and
 * checks newly installed packages while this service is running. Android does
 * not expose other apps' private data or a system-wide process/network hook.
 */
object ProtectionRuntime {
    private const val PREFS = "alai-protection-state"
    private const val KEY_ENABLED = "enabled"

    fun isEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_ENABLED, enabled).apply()
    }
}

class ProtectionService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val observers = CopyOnWriteArrayList<FileObserver>()
    private val watchedPaths = mutableSetOf<String>()
    private var packageReceiverRegistered = false

    private val packageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val packageName = intent?.data?.schemeSpecificPart ?: return
            if (packageName == packageNameForSelf()) return
            serviceScope.launch {
                delay(1_200L)
                scanInstalledPackage(packageName)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        startAsForeground()
        registerPackageMonitor()
        startFileMonitoring()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            ProtectionRuntime.setEnabled(this, false)
            stopSelf()
            return START_NOT_STICKY
        }
        if (!ProtectionRuntime.isEnabled(this)) {
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        observers.forEach { runCatching { it.stopWatching() } }
        observers.clear()
        if (packageReceiverRegistered) {
            runCatching { unregisterReceiver(packageReceiver) }
            packageReceiverRegistered = false
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startAsForeground() {
        val stopIntent = Intent(this, ProtectionService::class.java).setAction(ACTION_STOP)
        val stopPendingIntent = PendingIntent.getService(
            this, 4109, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("ANTIVIRUS AL AI · محافظت فعال")
            .setContentText("پایش فایل‌های قابل‌دسترسی و برنامه‌های تازه نصب‌شده")
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "توقف محافظت", stopPendingIntent)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "محافظت بلادرنگ", NotificationManager.IMPORTANCE_LOW).apply {
                description = "اعلان دائمی هنگام فعال بودن محافظت دستگاه"
                setShowBadge(false)
            }
        )
        manager.createNotificationChannel(
            NotificationChannel(ALERT_CHANNEL_ID, "هشدار تهدید", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "هشدار هنگام شناسایی فایل دارای شاخص تهدید"
            }
        )
    }

    private fun registerPackageMonitor() {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                registerReceiver(packageReceiver, filter, Context.RECEIVER_EXPORTED)
            } else {
                @Suppress("DEPRECATION")
                registerReceiver(packageReceiver, filter)
            }
            packageReceiverRegistered = true
        } catch (_: Exception) {
            packageReceiverRegistered = false
        }
    }

    private fun startFileMonitoring() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
            return
        }
        val storage = Environment.getExternalStorageDirectory()
        val targets = listOf(
            File(storage, "Download"),
            File(storage, "Downloads"),
            File(storage, "Documents"),
            File(storage, "Bluetooth"),
            File(storage, "DCIM"),
            File(storage, "Pictures"),
            File(storage, "Movies"),
            File(storage, "Android/media")
        )
        val visited = mutableSetOf<String>()
        targets.forEach { directory ->
            if (directory.isDirectory) watchTree(directory, depth = 0, visited = visited)
        }
    }

    private fun watchTree(directory: File, depth: Int, visited: MutableSet<String>) {
        if (depth > MAX_WATCH_DEPTH || observers.size >= MAX_WATCHERS) return
        val canonical = runCatching { directory.canonicalFile }.getOrNull() ?: return
        if (!canonical.isDirectory || !synchronized(visited) { visited.add(canonical.path) }) return
        synchronized(watchedPaths) {
            if (!watchedPaths.add(canonical.path)) return
        }

        val mask = FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO or FileObserver.CREATE
        try {
            val observer = object : FileObserver(canonical.absolutePath, mask) {
                override fun onEvent(event: Int, path: String?) {
                    val relative = path ?: return
                    val target = File(canonical, relative)
                    val isDirectory = (event and FileObserver.ISDIR) != 0
                    if (isDirectory && (event and FileObserver.CREATE) != 0) {
                        serviceScope.launch { watchTree(target, depth + 1, visited) }
                    } else if (!isDirectory &&
                        ((event and FileObserver.CLOSE_WRITE) != 0 || (event and FileObserver.MOVED_TO) != 0)
                    ) {
                        serviceScope.launch {
                            delay(1_000L)
                            scanFile(target)
                        }
                    }
                }
            }
            observer.startWatching()
            observers += observer
        } catch (_: Exception) {
            // One inaccessible directory must not stop the remaining watchers.
        }

        if (depth < MAX_WATCH_DEPTH && observers.size < MAX_WATCHERS) {
            runCatching { canonical.listFiles() }.getOrNull()
                ?.filter { it.isDirectory && !it.name.startsWith(".") }
                ?.forEach { watchTree(it, depth + 1, visited) }
        }
    }

    private suspend fun scanInstalledPackage(packageName: String) {
        try {
            val info = packageManager.getApplicationInfo(packageName, 0)
            val apk = info.sourceDir?.let(::File) ?: return
            if (apk.isFile) scanFile(apk, packageName)
        } catch (_: Exception) {
            // Android may hide or revoke access to an installed package's APK path.
        }
    }

    private suspend fun scanFile(file: File, displayName: String = file.name) {
        if (!file.isFile || !file.canRead() || file.length() <= 0L ||
            file.length() > ScanEngine.MAX_FILE_SIZE_BYTES
        ) return
        try {
            val result = ScanEngine.scan(applicationContext, Uri.fromFile(file))
            when (result.verdict) {
                ScanVerdict.KNOWN_MALWARE,
                ScanVerdict.POTENTIALLY_UNWANTED,
                ScanVerdict.SUSPICIOUS -> postThreatAlert(displayName, result.verdict)
                else -> Unit
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            // Inaccessible or unsupported files remain unverified; never mark them clean.
        }
    }

    private fun postThreatAlert(name: String, verdict: ScanVerdict) {
        val manager = getSystemService(NotificationManager::class.java)
        val label = when (verdict) {
            ScanVerdict.KNOWN_MALWARE -> "بدافزار شناخته‌شده"
            ScanVerdict.POTENTIALLY_UNWANTED -> "برنامه یا فایل ناخواسته"
            else -> "فایل مشکوک"
        }
        val notification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("ANTIVIRUS AL AI · $label")
            .setContentText(name)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$label شناسایی شد: $name. برای بررسی و تصمیم درباره قرنطینه، برنامه را باز کنید."))
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        manager.notify((name.hashCode() and 0x7fffffff).coerceAtLeast(1), notification)
    }

    private fun packageNameForSelf(): String = applicationContext.packageName

    companion object {
        const val ACTION_STOP = "com.antivirusalai.action.STOP_PROTECTION"
        private const val CHANNEL_ID = "alai-protection-service"
        private const val ALERT_CHANNEL_ID = "alai-protection-alerts"
        private const val NOTIFICATION_ID = 4108
        private const val MAX_WATCH_DEPTH = 2
        private const val MAX_WATCHERS = 96
    }
}

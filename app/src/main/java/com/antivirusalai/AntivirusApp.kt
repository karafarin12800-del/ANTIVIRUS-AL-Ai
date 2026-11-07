package com.antivirusalai

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.lifecycle.Observer
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.workDataOf
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.res.imageResource
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.antivirusalai.engine.FolderScanItem
import com.antivirusalai.engine.DeviceScanEngine
import com.antivirusalai.engine.FolderScanReport
import com.antivirusalai.engine.EvidenceSeverity
import com.antivirusalai.engine.ScanResult
import com.antivirusalai.engine.ScanVerdict
import com.antivirusalai.engine.ScanReportStore
import com.antivirusalai.remediation.QuarantineVault
import com.antivirusalai.intel.ThreatFeedRuntime
import com.antivirusalai.remediation.VaultEntry
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private val AppBackground = Color(0xFF0B0618)
private val SurfaceBase = Color(0xFF171027)
private val SurfaceRaised = Color(0xFF211437)
private val SurfaceSoft = Color(0xFF2B1948)
private val BrandTeal = Color(0xFFC69BFF)
private val BrandBlue = Color(0xFF873CFA)
private val TextPrimary = Color(0xFFF3F7FC)
private val TextSecondary = Color(0xFFB9ADC9)
private val TextTertiary = Color(0xFF8A7BA0)
private val ColorWarning = Color(0xFFF2C66D)
private val ColorDanger = Color(0xFFFF718C)
private val ColorSuccess = Color(0xFF58D99A)

private enum class MainTab(val key: String) {
    HOME("home"),
    SCAN("scan"),
    TOOLS("tools"),
    STORE("store"),
    SETTINGS("settings"),
    VAULT("vault")
}

@Composable
fun AntivirusApp(inPictureInPicture: Boolean = false) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val workManager = remember(context) { WorkManager.getInstance(context.applicationContext) }
    val restoredScan = remember(context) { ScanReportStore.load(context.applicationContext) }
    var language by rememberSaveable { mutableStateOf("fa") }
    var activeTab by rememberSaveable { mutableStateOf(MainTab.HOME.key) }
    var scanning by remember { mutableStateOf(false) }
    var quarantining by remember { mutableStateOf(false) }
    var showQuarantineConfirmation by remember { mutableStateOf(false) }
    var selectedUri by rememberSaveable { mutableStateOf<Uri?>(null) }
    var scanResult by remember { mutableStateOf<ScanResult?>(null) }
    var batchReport by remember { mutableStateOf<FolderScanReport?>(restoredScan?.report) }
    var batchProgress by remember { mutableStateOf<String?>(null) }
    var scanProgress by remember { mutableStateOf(0f) }
    var scanCurrent by remember { mutableStateOf(0) }
    var scanTotal by remember { mutableStateOf(0) }
    var scanStartedAtMs by remember { mutableStateOf(0L) }
    var scanElapsedMs by remember { mutableStateOf(0L) }
    var pendingDeepScan by remember { mutableStateOf(false) }
    var deviceScanDeep by remember { mutableStateOf(restoredScan?.deep ?: false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var notice by remember { mutableStateOf<String?>(null) }
    var selectedPlan by remember { mutableStateOf<String?>(null) }
    var featureInfo by remember { mutableStateOf<String?>(null) }
    var showPrivacy by remember { mutableStateOf(false) }
    var showStoragePermissionRationale by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }
    var vaultRefresh by remember { mutableStateOf(0) }
    var protectionEnabled by remember { mutableStateOf(ProtectionRuntime.isEnabled(context)) }
    val fa = language == "fa"

    val toggleProtection: (Boolean) -> Unit = { enabled ->
        if (enabled) {
            try {
                ProtectionRuntime.setEnabled(context, true)
                context.startForegroundService(Intent(context, ProtectionService::class.java))
                protectionEnabled = true
                notice = tr(
                    fa,
                    "محافظت فعال شد؛ اعلان دائمی وضعیت آن را نشان می‌دهد.",
                    "Protection is active; its ongoing notification shows the service status."
                )
            } catch (error: Exception) {
                ProtectionRuntime.setEnabled(context, false)
                protectionEnabled = false
                errorMessage = error.message ?: tr(
                    fa,
                    "سرویس محافظت شروع نشد. مجوز اعلان‌ها و تنظیمات Android را بررسی کن.",
                    "Protection could not start. Check notification permission and Android settings."
                )
            }
        } else {
            ProtectionRuntime.setEnabled(context, false)
            context.stopService(Intent(context, ProtectionService::class.java))
            protectionEnabled = false
            notice = tr(fa, "محافظت متوقف شد.", "Protection has been stopped.")
        }
    }

    LaunchedEffect(scanning, scanStartedAtMs) {
        while (scanning) {
            scanElapsedMs = (System.currentTimeMillis() - scanStartedAtMs).coerceAtLeast(0L)
            delay(1000L)
        }
    }

    val scanWorkInfoLiveData = remember(workManager) {
        workManager.getWorkInfosForUniqueWorkLiveData(DeviceScanWorker.WORK_NAME)
    }
    DisposableEffect(scanWorkInfoLiveData, context, fa) {
        val observer = Observer<List<WorkInfo>> { infos ->
            val info = infos.maxByOrNull { workInfo ->
            maxOf(
                workInfo.progress.getLong(DeviceScanWorker.KEY_STARTED_AT_MS, 0L),
                workInfo.outputData.getLong(DeviceScanWorker.KEY_STARTED_AT_MS, 0L)
            )
        }
            if (info != null) {
                val active = info.state == WorkInfo.State.ENQUEUED ||
                    info.state == WorkInfo.State.RUNNING ||
                    info.state == WorkInfo.State.BLOCKED
                val progressData = if (active) info.progress else info.outputData
                scanning = active
                ScanRuntime.isActive = active
                deviceScanDeep = progressData.getBoolean(DeviceScanWorker.KEY_DEEP, deviceScanDeep)
                val startedAt = progressData.getLong(DeviceScanWorker.KEY_STARTED_AT_MS, scanStartedAtMs)
                if (startedAt > 0L) scanStartedAtMs = startedAt

                scanCurrent = progressData.getInt(DeviceScanWorker.KEY_CURRENT, scanCurrent)
                scanTotal = progressData.getInt(DeviceScanWorker.KEY_TOTAL, scanTotal)
                scanProgress = if (scanTotal > 0) {
                    (scanCurrent.toFloat() / scanTotal.toFloat()).coerceIn(0f, 1f)
                } else if (info.state == WorkInfo.State.SUCCEEDED) 1f else 0f

                when (info.state) {
                    WorkInfo.State.ENQUEUED, WorkInfo.State.RUNNING, WorkInfo.State.BLOCKED -> {
                        batchProgress = progressData.getString(DeviceScanWorker.KEY_CURRENT_NAME)
                            ?: tr(fa, "در حال آماده‌سازی فهرست فایل‌ها…", "Preparing the file inventory…")
                    }
                    WorkInfo.State.SUCCEEDED -> {
                        val saved = ScanReportStore.load(context.applicationContext)
                        if (saved != null) {
                            batchReport = saved.report
                            deviceScanDeep = saved.deep
                        }
                        scanning = false
                        ScanRuntime.isActive = false
                        batchProgress = null
                    }
                    WorkInfo.State.FAILED -> {
                        errorMessage = info.outputData.getString(DeviceScanWorker.KEY_ERROR)
                            ?: tr(fa, "اسکن در پس‌زمینه کامل نشد.", "The background scan did not complete.")
                        scanning = false
                        ScanRuntime.isActive = false
                        batchProgress = null
                    }
                    WorkInfo.State.CANCELLED -> {
                        scanning = false
                        ScanRuntime.isActive = false
                        batchProgress = null
                    }
                }
            }
        }
        scanWorkInfoLiveData.observeForever(observer)
        onDispose { scanWorkInfoLiveData.removeObserver(observer) }
    }

    val executeDeviceScan: (Boolean) -> Unit = { deep ->
        val startedAt = System.currentTimeMillis()
        scanStartedAtMs = startedAt
        scanElapsedMs = 0L
        scanCurrent = 0
        scanTotal = 0
        scanning = true
        ScanRuntime.isActive = true
        deviceScanDeep = deep
        selectedUri = null
        scanResult = null
        batchReport = null
        ScanReportStore.clear(context.applicationContext)
        scanProgress = 0f
        batchProgress = tr(
            fa,
            "در حال آماده‌سازی فهرست فایل‌ها و برنامه‌های نصب‌شده…",
            "Preparing the file and installed-app inventory…"
        )
        errorMessage = null
        notice = null
        activeTab = MainTab.SCAN.key
        try {
            val request = OneTimeWorkRequestBuilder<DeviceScanWorker>()
                .setInputData(workDataOf(
                    DeviceScanWorker.KEY_DEEP to deep,
                    DeviceScanWorker.KEY_STARTED_AT_MS to startedAt
                ))
                .build()
            workManager.enqueueUniqueWork(
                DeviceScanWorker.WORK_NAME,
                ExistingWorkPolicy.REPLACE,
                request
            )
        } catch (error: Exception) {
            ScanRuntime.isActive = false
            scanning = false
            batchProgress = null
            errorMessage = error.message
                ?: tr(fa, "کار پس‌زمینهٔ اسکن شروع نشد.", "The background scan could not be started.")
        }
    }

    val storageSettingsLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (DeviceScanEngine.hasBroadStorageAccess()) {
            executeDeviceScan(pendingDeepScan)
        } else {
            // The user declined broad shared-storage access. Still scan readable
            // installed APK components and explicitly label the report as partial.
            executeDeviceScan(pendingDeepScan)
            notice = tr(
                fa,
                "دسترسی کامل حافظه فعال نشد؛ اسکن برنامه‌های نصب‌شده و APKهای قابل‌خواندن ادامه پیدا می‌کند. فایل‌های حافظه مشترک در این نوبت بررسی نمی‌شوند.",
                "All-files access was not granted. The scan will continue with readable installed-app APKs; shared-storage files are not included."
            )
        }
    }

    val legacyStoragePermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) executeDeviceScan(pendingDeepScan)
        else errorMessage = tr(
            fa,
            "مجوز خواندن حافظه داده نشد.",
            "Storage read permission was denied."
        )
    }

    val launchDeviceScan: (Boolean) -> Unit = { deep ->
        if (!scanning) {
            pendingDeepScan = deep
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                if (DeviceScanEngine.hasBroadStorageAccess()) {
                    executeDeviceScan(deep)
                } else {
                    showStoragePermissionRationale = true
                }
            } else if (context.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
            ) {
                executeDeviceScan(deep)
            } else {
                legacyStoragePermissionLauncher.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
            }
        }
    }

    val launchFileScan: () -> Unit = { launchDeviceScan(false) }
    val launchApkScan: () -> Unit = { launchDeviceScan(true) }

    val performQuarantine: () -> Unit = {
        showQuarantineConfirmation = false
        val uri = selectedUri
        val result = scanResult
        val actionableVerdicts = setOf(
            ScanVerdict.KNOWN_MALWARE,
            ScanVerdict.POTENTIALLY_UNWANTED,
            ScanVerdict.SUSPICIOUS
        )
        if (uri != null && result != null && !quarantining) {
            if (result.verdict !in actionableVerdicts) {
                // Defense in depth: never request source deletion for an unknown,
                // unsupported, clean-labelled, or harmless test-marker result.
                notice = tr(
                    fa,
                    "برای این نتیجه شواهد کافی جهت قرنطینه همراه با حذف فایل اصلی وجود ندارد؛ فایل مبدأ دست‌نخورده باقی ماند.",
                    "This result does not contain enough evidence for quarantine with source removal. The original file was left untouched."
                )
            } else {
                quarantining = true
                scope.launch {
                    try {
                        val receipt = QuarantineVault.quarantineAndRemoveSource(
                            context.applicationContext,
                            uri,
                            result.sha256
                        )
                        notice = if (receipt.sourceRemoved) {
                            tr(
                                fa,
                                "نسخه رمزنگاری‌شده و تأییدشده در قرنطینه ذخیره شد و Android حذف فایل مبدأ را تأیید کرد.",
                                "A verified encrypted copy was stored in quarantine and Android confirmed source removal."
                            )
                        } else {
                            tr(
                                fa,
                                "نسخه رمزنگاری‌شده در قرنطینه ذخیره شد؛ اما Android یا ارائه‌دهنده فایل اجازه حذف مبدأ را نداد. فایل اصلی ممکن است هنوز روی دستگاه باشد.",
                                "The encrypted quarantine copy was saved, but Android or the file provider did not allow source deletion. The original may still be on the device."
                            )
                        }
                        if (receipt.sourceRemoved) selectedUri = null
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (error: Exception) {
                        notice = error.message
                            ?: tr(fa, "عملیات قرنطینه انجام نشد.", "Quarantine operation failed.")
                    } finally {
                        quarantining = false
                    }
                }
            }
        }
    }

    CompositionLocalProvider(
        LocalLayoutDirection provides if (fa) LayoutDirection.Rtl else LayoutDirection.Ltr
    ) {
        MaterialTheme(
            colorScheme = darkColorScheme(
                primary = BrandTeal,
                onPrimary = AppBackground,
                background = AppBackground,
                surface = SurfaceBase,
                onSurface = TextPrimary,
                secondary = BrandBlue,
                error = ColorDanger
            )
        ) {
            Scaffold(
                containerColor = AppBackground,
                bottomBar = {
                    if (!inPictureInPicture) {
                        MainNavigationBar(
                            activeTab = activeTab,
                            fa = fa,
                            onSelect = { activeTab = it.key }
                        )
                    }
                }
            ) { insets ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.verticalGradient(
                                colors = listOf(Color(0xFF1B0B31), Color(0xFF11091F), AppBackground)
                            )
                        )
                        .padding(insets)
                ) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val w = size.width
                        val h = size.height
                        val a = Offset(w * 0.98f, h * 0.06f)
                        val b = Offset(w * 0.02f, h * 0.62f)
                        drawCircle(
                            brush = Brush.radialGradient(
                                listOf(Color(0xFF9A55F2).copy(alpha = 0.24f), Color.Transparent),
                                center = a, radius = w * 0.92f
                            ),
                            radius = w * 0.92f, center = a
                        )
                        drawCircle(
                            brush = Brush.radialGradient(
                                listOf(Color(0xFF6731A7).copy(alpha = 0.18f), Color.Transparent),
                                center = b, radius = w * 0.88f
                            ),
                            radius = w * 0.88f, center = b
                        )
                        drawOval(
                            color = Color(0xFFC99EFF).copy(alpha = 0.035f),
                            topLeft = Offset(w * 0.38f, h * 0.07f),
                            size = Size(w * 0.94f, h * 0.29f)
                        )
                        val upperOrbit = Path().apply {
                            moveTo(-w * 0.13f, h * 0.24f)
                            cubicTo(w * 0.18f, h * 0.09f, w * 0.72f, h * 0.37f, w * 1.11f, h * 0.18f)
                        }
                        drawPath(upperOrbit, Color(0xFFD2A9FF).copy(alpha = 0.08f),
                            style = Stroke(width = 1.1f))
                        val lowerOrbit = Path().apply {
                            moveTo(-w * 0.12f, h * 0.77f)
                            cubicTo(w * 0.30f, h * 0.61f, w * 0.71f, h * 0.92f, w * 1.12f, h * 0.73f)
                        }
                        drawPath(lowerOrbit, Color(0xFFA77BDA).copy(alpha = 0.06f),
                            style = Stroke(width = 1f))
                        val stars = listOf(
                            Offset(w * 0.12f, h * 0.08f), Offset(w * 0.82f, h * 0.12f),
                            Offset(w * 0.91f, h * 0.29f), Offset(w * 0.17f, h * 0.43f),
                            Offset(w * 0.78f, h * 0.55f), Offset(w * 0.89f, h * 0.70f),
                            Offset(w * 0.23f, h * 0.82f), Offset(w * 0.62f, h * 0.94f),
                            Offset(w * 0.47f, h * 0.18f), Offset(w * 0.06f, h * 0.93f)
                        )
                        stars.forEachIndexed { index, point ->
                            drawCircle(
                                Color(0xFFEAD8FF).copy(alpha = if (index % 3 == 0) 0.38f else 0.18f),
                                radius = if (index % 3 == 0) 1.9f else 1.1f,
                                center = point
                            )
                        }
                    }
                    if (inPictureInPicture) {
                        ScanPictureInPicturePreview(
                            fa = fa,
                            progress = scanProgress,
                            current = scanCurrent,
                            total = scanTotal,
                            scanning = scanning
                        )
                    } else {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(horizontal = 18.dp, vertical = 15.dp),
                        verticalArrangement = Arrangement.spacedBy(22.dp)
                    ) {
                        BrandHeader(
                            fa = fa,
                            onLanguageChange = { language = if (fa) "en" else "fa" },
                            onSettings = { activeTab = MainTab.SETTINGS.key }
                        )

                        when (activeTab) {
                            MainTab.HOME.key -> DashboardScreen(
                                fa = fa,
                                scanning = scanning,
                                result = scanResult,
                                batchReport = batchReport,
                                protectionEnabled = protectionEnabled,
                                onOpenScan = { activeTab = MainTab.SCAN.key },
                                onFileScan = launchFileScan,
                                onApkScan = launchApkScan,
                                onOpenTools = { activeTab = MainTab.TOOLS.key },
                                onOpenStore = { activeTab = MainTab.STORE.key },
                                onOpenSettings = { activeTab = MainTab.SETTINGS.key }
                            )

                            MainTab.SCAN.key -> ScanCenterScreen(
                                fa = fa,
                                scanning = scanning,
                                result = scanResult,
                                batchReport = batchReport,
                                batchProgress = batchProgress,
                                scanProgress = scanProgress,
                                scanCurrent = scanCurrent,
                                scanTotal = scanTotal,
                                scanElapsedMs = scanElapsedMs,
                                deviceScanDeep = deviceScanDeep,
                                errorMessage = errorMessage,
                                notice = notice,
                                quarantining = quarantining,
                                onFileScan = launchFileScan,
                                onApkScan = launchApkScan,
                                onSelectBatchItem = { item ->
                                    selectedUri = item.uri
                                    scanResult = item.result
                                },
                                onQuarantine = { showQuarantineConfirmation = true },
                                onClearReport = {
                                    scanResult = null
                                    selectedUri = null
                                    batchReport = null
                                    errorMessage = null
                                    notice = null
                                }
                            )

                            MainTab.TOOLS.key -> SecurityToolsScreen(
                                fa = fa,
                                result = scanResult,
                                protectionEnabled = protectionEnabled,
                                onToggleProtection = toggleProtection,
                                onOpenScan = { activeTab = MainTab.SCAN.key },
                                onOpenVault = { activeTab = MainTab.VAULT.key }
                            )

                            MainTab.VAULT.key -> QuarantineVaultScreen(
                                fa = fa,
                                refreshKey = vaultRefresh,
                                onDelete = { id ->
                                    if (QuarantineVault.delete(context.applicationContext, id)) {
                                        vaultRefresh++
                                    }
                                }
                            )

                            MainTab.STORE.key -> StoreScreen(
                                fa = fa,
                                onSelectPlan = { selectedPlan = it }
                            )

                            else -> SettingsScreen(
                                fa = fa,
                                onLanguageChange = { language = if (fa) "en" else "fa" },
                                onPrivacy = { showPrivacy = true },
                                onAbout = { showAbout = true },
                                onFeature = { featureInfo = it }
                            )
                        }

                        Text(
                            tr(
                                fa,
                                "ANTIVIRUS AL AI  •  نسخه آزمایشی ${BuildConfig.VERSION_NAME}",
                                "ANTIVIRUS AL AI  •  DEVELOPMENT BUILD ${BuildConfig.VERSION_NAME}"
                            ),
                            color = TextTertiary,
                            fontSize = 10.sp,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth().padding(bottom = 7.dp)
                        )
                    }
                    }
                }
            }
        }
    }

    selectedPlan?.let { plan ->
        AlertDialog(
            onDismissRequest = { selectedPlan = null },
            containerColor = SurfaceRaised,
            title = { Text(tr(fa, "فروشگاه ANTIVIRUS AL AI", "ANTIVIRUS AL AI Store"), color = TextPrimary) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
                    Text(
                        tr(fa, "طرح انتخاب‌شده: $plan", "Selected plan: $plan"),
                        color = BrandTeal,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        tr(
                            fa,
                            "پرداخت Google Play و مدیریت اشتراک هنوز متصل نشده‌اند. هیچ مبلغی دریافت یا اشتراکی فعال نمی‌شود. این بخش فعلاً پیش‌نمایش طرح‌هاست.",
                            "Google Play Billing and subscription management are not connected yet. No payment or subscription activation will occur. This is currently a plan preview."
                        ),
                        color = TextSecondary
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = { selectedPlan = null },
                    colors = ButtonDefaults.buttonColors(containerColor = BrandTeal)
                ) { Text(tr(fa, "متوجه شدم", "Got it"), color = AppBackground) }
            }
        )
    }

    featureInfo?.let { feature ->
        AlertDialog(
            onDismissRequest = { featureInfo = null },
            containerColor = SurfaceRaised,
            title = { Text(featureTitle(fa, feature), color = TextPrimary) },
            text = { Text(featureDescription(fa, feature), color = TextSecondary) },
            confirmButton = {
                Button(
                    onClick = { featureInfo = null },
                    colors = ButtonDefaults.buttonColors(containerColor = BrandTeal)
                ) { Text(tr(fa, "بستن", "Close"), color = AppBackground) }
            }
        )
    }

    if (showStoragePermissionRationale) {
        AlertDialog(
            onDismissRequest = { showStoragePermissionRationale = false },
            containerColor = SurfaceRaised,
            title = {
                Text(
                    tr(fa, "اجازه اسکن حافظه", "Allow device scanning"),
                    color = TextPrimary
                )
            },
            text = {
                Text(
                    tr(
                        fa,
                        "برای اسکن گسترده فایل‌های حافظه، Android مسیر رسمی «مدیریت همه فایل‌ها» را دارد. همچنین فهرست برنامه‌های نصب‌شده برای بررسی امنیتی محلی استفاده می‌شود. فایل‌ها و فهرست برنامه‌ها آپلود یا برای تبلیغات استفاده نمی‌شوند. با رد مجوز حافظه، برنامه همچنان APKهای نصب‌شده‌ای را که مسیر خواندنشان در دسترس باشد بررسی می‌کند؛ اما فایل‌های حافظه مشترک در این نوبت اسکن نمی‌شوند. پوشه‌های خصوصی برنامه‌های دیگر و Android/data و Android/obb همچنان خارج از دسترس هستند.",
                        "Android provides the official All files access setting for broad shared-storage scanning. The installed-app inventory is also used for local security review. Files and app inventory are not uploaded or used for advertising. If broad storage access is declined, the app still checks installed APK components whose paths are readable, but shared-storage files are not scanned in that run. Other apps’ private folders and Android/data and Android/obb remain excluded."
                    ),
                    color = TextSecondary
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showStoragePermissionRationale = false
                        val appSettingsIntent = Intent(
                            Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                            Uri.parse("package:${context.packageName}")
                        )
                        try {
                            storageSettingsLauncher.launch(appSettingsIntent)
                        } catch (_: Exception) {
                            storageSettingsLauncher.launch(
                                Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                            )
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = BrandTeal)
                ) {
                    Text(tr(fa, "رفتن به تنظیمات", "Open settings"), color = AppBackground)
                }
            },
            dismissButton = {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = {
                            showStoragePermissionRationale = false
                            executeDeviceScan(pendingDeepScan)
                            notice = tr(
                                fa,
                                "اسکن محدود برنامه‌های نصب‌شده شروع شد؛ حافظه مشترک بررسی نمی‌شود.",
                                "Installed-app-only scan started; shared storage is not included."
                            )
                        }
                    ) {
                        Text(tr(fa, "فقط اسکن برنامه‌ها", "Scan apps only"), color = TextPrimary)
                    }
                    OutlinedButton(onClick = { showStoragePermissionRationale = false }) {
                        Text(tr(fa, "انصراف", "Cancel"), color = TextPrimary)
                    }
                }
            }
        )
    }

    if (showPrivacy) {
        AlertDialog(
            onDismissRequest = { showPrivacy = false },
            containerColor = SurfaceRaised,
            title = { Text(tr(fa, "حریم خصوصی و داده‌ها", "Privacy and data"), color = TextPrimary) },
            text = {
                Text(
                    tr(
                        fa,
                        "اسکن خودکار فقط پس از شروع توسط کاربر انجام می‌شود. فایل‌های قابل‌دسترسی حافظه اشتراکی و فهرست برنامه‌های نصب‌شده برای بررسی امنیتی روی خود دستگاه پردازش می‌شوند؛ محتوای فایل‌ها یا فهرست برنامه‌ها به سرور ارسال یا برای تبلیغات استفاده نمی‌شوند. Android همچنان پوشه‌های خصوصی برنامه‌های دیگر و Android/data و Android/obb را مسدود می‌کند. قرنطینه پس از تأیید کاربر نسخه رمزنگاری‌شده را بررسی می‌کند و فقط در صورت اجازه Android برای حذف منبع تلاش می‌کند.",
                        "Scanning starts only when the user requests it. Accessible shared-storage files and the installed-app inventory are processed locally for security review; file contents and the app inventory are not sent to a server or used for advertising. Android still blocks other apps' private folders and protected areas such as Android/data and Android/obb. Quarantine verifies an encrypted copy first and attempts source deletion only after user confirmation and when Android permits it."
                    ),
                    color = TextSecondary
                )
            },
            confirmButton = {
                Button(onClick = { showPrivacy = false }) {
                    Text(tr(fa, "بستن", "Close"), color = AppBackground)
                }
            }
        )
    }

    if (showAbout) {
        AlertDialog(
            onDismissRequest = { showAbout = false },
            containerColor = SurfaceRaised,
            title = { Text("ANTIVIRUS AL AI", color = TextPrimary) },
            text = {
                Text(
                    tr(
                        fa,
                        "نسخه ${BuildConfig.VERSION_NAME} • ابزارهای امنیتی برای بررسی و نگهداری امن دستگاه.",
                        "Version ${BuildConfig.VERSION_NAME} • Security tools to inspect and help protect your device."
                    ),
                    color = TextSecondary
                )
            },
            confirmButton = {
                Button(onClick = { showAbout = false }) {
                    Text(tr(fa, "بستن", "Close"), color = AppBackground)
                }
            }
        )
    }

    if (showQuarantineConfirmation) {
        AlertDialog(
            onDismissRequest = { showQuarantineConfirmation = false },
            containerColor = SurfaceRaised,
            title = { Text(tr(fa, "تأیید قرنطینه و حذف", "Confirm quarantine and removal"), color = TextPrimary) },
            text = {
                Text(
                    tr(
                        fa,
                        "ابتدا یک نسخه رمزنگاری‌شده AES-GCM ساخته و هش آن تأیید می‌شود؛ سپس برنامه فقط از Android یا ارائه‌دهنده فایل درخواست حذف فایل مبدأ را می‌کند. حذف ممکن است به‌دلیل محدودیت مجوز ناموفق باشد. این عملیات برنامه نصب‌شده را uninstall نمی‌کند و حذف امن فیزیکی روی حافظه فلش تضمین‌پذیر نیست.",
                        "ANTIVIRUS AL AI first creates and verifies an AES-GCM encrypted copy, then asks Android or the file provider to remove the source. Deletion can fail because of permission restrictions. This does not uninstall installed apps, and physical secure erasure cannot be guaranteed on flash storage."
                    ),
                    color = TextSecondary
                )
            },
            confirmButton = {
                Button(
                    onClick = performQuarantine,
                    colors = ButtonDefaults.buttonColors(containerColor = ColorDanger)
                ) {
                    Text(tr(fa, "قرنطینه و تلاش برای حذف", "Quarantine and attempt removal"), color = AppBackground)
                }
            },
            dismissButton = {
                OutlinedButton(onClick = { showQuarantineConfirmation = false }) {
                    Text(tr(fa, "انصراف", "Cancel"), color = TextPrimary)
                }
            }
        )
    }
}

@Composable
private fun BrandHeader(
    fa: Boolean,
    onLanguageChange: () -> Unit,
    onSettings: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(11.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(52.dp)
                    .background(
                        Brush.linearGradient(listOf(Color(0xFFE4C2FF), Color(0xFF8B42E8), Color(0xFF4D1B91))),
                        RoundedCornerShape(18.dp)
                    )
                    .border(1.dp, Color(0xFFE8D4FF).copy(alpha = 0.35f), RoundedCornerShape(18.dp)),
                contentAlignment = Alignment.Center
            ) {
                EnergyShieldMark(Modifier.size(35.dp))
            }
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    "ANTIVIRUS AL AI",
                    color = TextPrimary,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 0.25.sp
                )
                Text(
                    tr(fa, "امنیت هوشمند • همیشه همراه شما", "Smart Security • Always With You"),
                    color = TextTertiary,
                    fontSize = 9.sp,
                    letterSpacing = 0.65.sp
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
            HeaderAction(label = if (fa) "EN" else "فا", onClick = onLanguageChange)
            HeaderAction(icon = "settings", onClick = onSettings)
        }
    }
}

@Composable
private fun HeaderAction(
    label: String? = null,
    icon: String? = null,
    onClick: () -> Unit
) {
    Surface(
        modifier = Modifier.size(40.dp).clickable(onClick = onClick),
        color = SurfaceBase,
        shape = RoundedCornerShape(13.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, Color.White.copy(alpha = 0.04f))
    ) {
        Box(contentAlignment = Alignment.Center) {
            if (icon != null) {
                IconArt(icon, tint = BrandTeal, size = 19.dp)
            } else {
                Text(label.orEmpty(), color = BrandTeal, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun MainNavigationBar(
    activeTab: String,
    fa: Boolean,
    onSelect: (MainTab) -> Unit
) {
    NavigationBar(
        containerColor = Color(0xFF171021),
        contentColor = TextPrimary,
        tonalElevation = 0.dp
    ) {
        val items = listOf(
            NavItem(MainTab.HOME, "home", tr(fa, "خانه", "Home")),
            NavItem(MainTab.SCAN, "scan", tr(fa, "اسکن", "Scan")),
            NavItem(MainTab.TOOLS, "tools", tr(fa, "ابزارها", "Tools")),
            NavItem(MainTab.STORE, "store", tr(fa, "فروشگاه", "Store")),
            NavItem(MainTab.SETTINGS, "settings", tr(fa, "تنظیمات", "Settings"))
        )
        items.forEach { item ->
            NavigationBarItem(
                selected = activeTab == item.tab.key,
                onClick = { onSelect(item.tab) },
                icon = {
                    IconArt(
                        item.icon,
                        tint = if (activeTab == item.tab.key) BrandTeal else TextTertiary,
                        size = 22.dp
                    )
                },
                label = { Text(item.label, fontSize = 10.sp, maxLines = 1) },
                alwaysShowLabel = true,
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = BrandTeal,
                    selectedTextColor = BrandTeal,
                    indicatorColor = BrandTeal.copy(alpha = 0.11f),
                    unselectedIconColor = TextTertiary,
                    unselectedTextColor = TextTertiary
                )
            )
        }
    }
}

private data class NavItem(val tab: MainTab, val icon: String, val label: String)

@Composable
private fun DashboardScreen(
    fa: Boolean,
    scanning: Boolean,
    result: ScanResult?,
    batchReport: FolderScanReport?,
    protectionEnabled: Boolean,
    onOpenScan: () -> Unit,
    onFileScan: () -> Unit,
    onApkScan: () -> Unit,
    onOpenTools: () -> Unit,
    onOpenStore: () -> Unit,
    onOpenSettings: () -> Unit
) {
    val context = LocalContext.current
    val currentThreatFeed = ThreatFeedRuntime.currentFeed(context)
    Column(verticalArrangement = Arrangement.spacedBy(23.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                EyebrowLabel(tr(fa, "AL AI  /  مرکز فرماندهی", "AL AI  /  SECURITY COMMAND"))
                StatusBadge(
                    text = tr(fa, "نسخه ${BuildConfig.VERSION_NAME}", "VERSION ${BuildConfig.VERSION_NAME}"),
                    tint = TextTertiary
                )
            }
            Text(
                tr(fa, "نگهبان هوشمند دستگاه", "Your digital guardian"),
                color = TextPrimary,
                fontSize = 25.sp,
                fontWeight = FontWeight.ExtraBold,
                letterSpacing = (-0.25).sp
            )
            Text(
                tr(fa, "یک نگاه روشن به وضعیت امنیت و ابزارهای دستگاهت", "A clear view of your device security and tools"),
                color = TextSecondary,
                fontSize = 12.sp
            )
        }

        HeroSecurityCard(
            fa = fa,
            scanning = scanning,
            report = batchReport,
            onOpenScan = onOpenScan,
            onScan = onFileScan,
            onApk = onApkScan
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(9.dp)
        ) {
            DashboardShortcutCard(
                modifier = Modifier.weight(1f),
                icon = "scan",
                label = tr(fa, "گزارش‌ها", "Reports"),
                onClick = onOpenScan
            )
            DashboardShortcutCard(
                modifier = Modifier.weight(1f),
                icon = "shield",
                label = tr(fa, "محافظت هوشمند", "Smart guard"),
                onClick = onOpenTools
            )
            DashboardShortcutCard(
                modifier = Modifier.weight(1f),
                icon = "lock",
                label = tr(fa, "قرنطینه", "Quarantine"),
                onClick = onOpenScan
            )
            DashboardShortcutCard(
                modifier = Modifier.weight(1f),
                icon = "settings",
                label = tr(fa, "تنظیمات", "Settings"),
                onClick = onOpenSettings
            )
        }

        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SectionTitle(
                title = tr(fa, "وضعیت لایه‌های امنیتی", "Security layers"),
                detail = tr(fa, "وضعیت واقعی قابلیت‌های فعال", "Live status of implemented capabilities")
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatusCard(
                    modifier = Modifier.weight(1f),
                    icon = "scan",
                    title = tr(fa, "موتور اسکن", "Scan engine"),
                    value = tr(fa, "آماده", "Ready"),
                    detail = tr(fa, "تحلیل محلی فایل‌ها", "On-device file analysis"),
                    tint = BrandTeal
                )
                StatusCard(
                    modifier = Modifier.weight(1f),
                    icon = "database",
                    title = tr(fa, "بانک تهدید", "Threat intelligence"),
                    value = if (currentThreatFeed != null) tr(fa, "متصل", "Connected") else tr(fa, "در انتظار اتصال", "Pending"),
                    detail = if (currentThreatFeed != null) {
                        tr(fa, "${currentThreatFeed.indicators.size} شاخص · نسخه ${currentThreatFeed.version}", "${currentThreatFeed.indicators.size} indicators · v${currentThreatFeed.version}")
                    } else {
                        tr(fa, "بانک امضاشده هنوز منتشر نشده", "Signed feed has not been published")
                    },
                    tint = if (currentThreatFeed != null) ColorSuccess else ColorWarning
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatusCard(
                    modifier = Modifier.weight(1f),
                    icon = "activity",
                    title = tr(fa, "محافظت بلادرنگ", "Real-time guard"),
                    value = if (protectionEnabled) tr(fa, "فعال", "Active") else tr(fa, "غیرفعال", "Inactive"),
                    detail = if (protectionEnabled) {
                        tr(fa, "پایش فایل‌های قابل‌دسترسی و نصب برنامه‌ها", "Monitoring accessible files and app installs")
                    } else {
                        tr(fa, "برای فعال‌سازی به ابزار امنیتی برو", "Enable it from the security toolkit")
                    },
                    tint = if (protectionEnabled) ColorSuccess else ColorWarning
                )
                StatusCard(
                    modifier = Modifier.weight(1f),
                    icon = "lock",
                    title = tr(fa, "حریم خصوصی", "Privacy"),
                    value = tr(fa, "محلی", "On-device"),
                    detail = tr(fa, "بدون آپلود محتوای فایل", "File contents stay local"),
                    tint = ColorSuccess
                )
            }
        }

        if (result != null) {
            RecentScanCard(fa = fa, result = result, onClick = onOpenScan)
        }

        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SectionTitle(
                title = tr(fa, "راه‌های شروع", "Start a scan"),
                detail = tr(fa, "بدون انتخاب دستی پوشه", "No manual folder selection")
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                QuickActionCard(
                    modifier = Modifier.weight(1f),
                    icon = "file",
                    title = tr(fa, "اسکن سریع", "Quick scan"),
                    caption = tr(fa, "مسیرهای رایج", "Common locations"),
                    onClick = onFileScan
                )
                QuickActionCard(
                    modifier = Modifier.weight(1f),
                    icon = "apk",
                    title = tr(fa, "اسکن عمیق", "Deep scan"),
                    caption = tr(fa, "پوشش گسترده‌تر", "Broader coverage"),
                    onClick = onApkScan
                )
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            SectionTitle(
                title = tr(fa, "ابزارهای نگهبان", "Guardian toolkit"),
                detail = tr(fa, "ماژول‌های فعلی و در حال توسعه", "Available and upcoming modules"),
                action = tr(fa, "همه ابزارها", "All tools"),
                onAction = onOpenTools
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MiniFeatureCard(
                    modifier = Modifier.weight(1f),
                    icon = "lock",
                    title = tr(fa, "قرنطینه امن", "Secure quarantine"),
                    subtitle = tr(fa, "نسخه رمزنگاری‌شده", "Encrypted copy"),
                    status = tr(fa, "پایه‌ای", "Basic"),
                    tint = BrandTeal
                )
                MiniFeatureCard(
                    modifier = Modifier.weight(1f),
                    icon = "shield",
                    title = tr(fa, "تحلیل APK", "APK analysis"),
                    subtitle = tr(fa, "بررسی ایستای برنامه", "Static app inspection"),
                    status = tr(fa, "در توسعه", "In progress"),
                    tint = ColorWarning
                )
            }
        }

        StorePromoCard(fa = fa, onClick = onOpenStore)

        InfoBanner(
            title = tr(fa, "شفافیت در گزارش امنیت", "Transparent security reporting"),
            body = tr(
                fa,
                "اسکن فقط فایل‌ها و مسیرهایی را بررسی می‌کند که Android در اختیار برنامه می‌گذارد. داده خصوصی برنامه‌های دیگر و پوشه‌های Android/data و Android/obb قابل‌دسترسی نیستند. نتیجه «بدون نشانگر شناخته‌شده» تضمین پاک بودن فایل نیست.",
                "Scans only inspect files and locations Android makes accessible. Other apps' private data and Android/data or Android/obb remain blocked. “No known indicator” does not guarantee a file is safe."
            ),
            warning = true
        )
    }
}

@Composable
private fun HeroSecurityCard(
    fa: Boolean,
    scanning: Boolean,
    report: FolderScanReport?,
    onOpenScan: () -> Unit,
    onScan: () -> Unit,
    onApk: () -> Unit
) {
    val cardShape = RoundedCornerShape(31.dp)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Color(0xFFCA9AFF).copy(alpha = 0.34f), cardShape),
        shape = cardShape,
        colors = CardDefaults.cardColors(containerColor = Color(0xFF1A0D2B))
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.verticalGradient(
                        listOf(Color(0xFF3D1D64), Color(0xFF281344), Color(0xFF160C28))
                    )
                )
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(250.dp)
            ) {
                Canvas(Modifier.matchParentSize()) {
                    val w = size.width
                    val h = size.height
                    val center = Offset(w * 0.50f, h * 0.52f)
                    drawCircle(
                        brush = Brush.radialGradient(
                            listOf(
                                Color(0xFFE4C0FF).copy(alpha = 0.30f),
                                Color(0xFFA35BEF).copy(alpha = 0.16f),
                                Color(0xFF5E2A92).copy(alpha = 0.05f),
                                Color.Transparent
                            ),
                            center = center,
                            radius = h * 0.76f
                        ),
                        radius = h * 0.76f,
                        center = center
                    )
                    // Layered orbital rings behind the guardian.
                    listOf(0.79f, 0.66f, 0.54f).forEachIndexed { index, factor ->
                        drawCircle(
                            color = Color(0xFFD8B5FF).copy(alpha = 0.15f - index * 0.025f),
                            radius = h * factor,
                            center = center,
                            style = Stroke(width = if (index == 0) 1.15f else 0.8f)
                        )
                    }
                    val orbit = Path().apply {
                        moveTo(w * 0.04f, h * 0.62f)
                        cubicTo(w * 0.26f, h * 0.02f, w * 0.78f, h * 0.06f, w * 0.97f, h * 0.60f)
                    }
                    drawPath(orbit, Color(0xFFC69BFF).copy(alpha = 0.30f),
                        style = Stroke(width = 1.35f))
                    val orbit2 = Path().apply {
                        moveTo(w * 0.10f, h * 0.38f)
                        cubicTo(w * 0.35f, h * 0.94f, w * 0.78f, h * 0.98f, w * 0.91f, h * 0.37f)
                    }
                    drawPath(orbit2, Color(0xFF9B67D6).copy(alpha = 0.20f),
                        style = Stroke(width = 1f))
                    val stars = listOf(
                        Offset(w * 0.14f, h * 0.32f), Offset(w * 0.24f, h * 0.15f),
                        Offset(w * 0.80f, h * 0.20f), Offset(w * 0.90f, h * 0.52f),
                        Offset(w * 0.18f, h * 0.73f), Offset(w * 0.77f, h * 0.77f),
                        Offset(w * 0.37f, h * 0.12f), Offset(w * 0.63f, h * 0.87f)
                    )
                    stars.forEachIndexed { index, point ->
                        drawCircle(
                            Color(0xFFF1DFFF).copy(alpha = if (index % 3 == 0) 0.74f else 0.34f),
                            radius = if (index % 3 == 0) 2.3f else 1.25f,
                            center = point
                        )
                    }
                    // A subtle faceted shield silhouette gives the scene a focal halo.
                    val haloShield = Path().apply {
                        moveTo(w * 0.50f, h * 0.08f)
                        lineTo(w * 0.75f, h * 0.18f)
                        lineTo(w * 0.72f, h * 0.54f)
                        cubicTo(w * 0.68f, h * 0.77f, w * 0.56f, h * 0.88f, w * 0.50f, h * 0.92f)
                        cubicTo(w * 0.44f, h * 0.88f, w * 0.32f, h * 0.77f, w * 0.28f, h * 0.54f)
                        lineTo(w * 0.25f, h * 0.18f)
                        close()
                    }
                    drawPath(haloShield, Color(0xFFD7B5FF).copy(alpha = 0.055f))
                    drawPath(haloShield, Color(0xFFE5CEFF).copy(alpha = 0.20f),
                        style = Stroke(width = 1.1f))
                }

                Image(
                    painter = painterResource(id = R.drawable.guardian_robot),
                    contentDescription = tr(fa, "ربات دکتر هوش مصنوعی", "AI doctor robot"),
                    modifier = Modifier
                        .align(Alignment.Center)
                        .padding(top = 13.dp)
                        .size(width = 174.dp, height = 188.dp),
                    contentScale = ContentScale.Fit
                )
            }

            Column(
                modifier = Modifier.padding(horizontal = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(9.dp)
            ) {
                Text(
                    tr(fa, "نگهبان هوشمند AL AI", "The AL AI guardian"),
                    color = TextPrimary,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.ExtraBold,
                    textAlign = TextAlign.Center
                )
                Text(
                    tr(
                        fa,
                        "امنیت دستگاهت را با اسکن سریع یا تحلیل عمیق فایل‌های قابل‌دسترسی بررسی کن.",
                        "Review your device with quick scans or deeper inspection of accessible files."
                    ),
                    color = Color(0xFFD0C0E4),
                    fontSize = 12.sp,
                    lineHeight = 19.sp,
                    textAlign = TextAlign.Center
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    GuardianValuePill(
                        icon = "lock",
                        label = tr(fa, "محلی", "LOCAL")
                    )
                    Spacer(Modifier.width(7.dp))
                    GuardianValuePill(
                        icon = "activity",
                        label = tr(fa, "شفاف", "CLEAR")
                    )
                    Spacer(Modifier.width(7.dp))
                    GuardianValuePill(
                        icon = "check",
                        label = tr(fa, "مبتنی بر شواهد", "EVIDENCE")
                    )
                }
            }

            HomeSafetyStatusCard(
                fa = fa,
                scanning = scanning,
                report = report,
                onOpenScan = onOpenScan
            )

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 17.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = onScan,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp)
                        .background(
                            Brush.horizontalGradient(
                                listOf(Color(0xFFE9D4FF), Color(0xFFC18BFF), Color(0xFF9857EA))
                            ),
                            RoundedCornerShape(18.dp)
                        ),
                    shape = RoundedCornerShape(18.dp),
                    contentPadding = PaddingValues(horizontal = 17.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.Transparent,
                        contentColor = Color(0xFF241036)
                    ),
                    elevation = ButtonDefaults.buttonElevation(
                        defaultElevation = 0.dp,
                        pressedElevation = 0.dp
                    )
                ) {
                    IconArt("lightning", tint = Color(0xFF49216E), size = 18.dp)
                    Spacer(Modifier.width(10.dp))
                    Text(
                        if (scanning) tr(fa, "در حال اسکن…", "Scanning…")
                        else tr(fa, "اسکن سریع", "Quick scan"),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Spacer(Modifier.width(9.dp))
                    IconArt("search", tint = Color(0xFF49216E), size = 18.dp)
                }

                OutlinedButton(
                    onClick = onApk,
                    modifier = Modifier.fillMaxWidth().height(49.dp),
                    shape = RoundedCornerShape(17.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp),
                    border = androidx.compose.foundation.BorderStroke(
                        1.dp, Color(0xFFDCC1FF).copy(alpha = 0.36f)
                    ),
                    colors = ButtonDefaults.outlinedButtonColors(
                        containerColor = Color(0xFF170D2B).copy(alpha = 0.30f),
                        contentColor = Color(0xFFE9D9FF)
                    )
                ) {
                    IconArt("apps", tint = Color(0xFFC69BFF), size = 17.dp)
                    Spacer(Modifier.width(9.dp))
                    Text(
                        tr(fa, "اسکن عمیق", "Deep scan"),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
            Spacer(Modifier.height(2.dp))
        }
    }
}

@Composable
private fun GuardianValuePill(icon: String, label: String) {
    Row(
        modifier = Modifier
            .background(Color(0xFFD6B8FF).copy(alpha = 0.075f), RoundedCornerShape(50))
            .border(1.dp, Color(0xFFDCC6FF).copy(alpha = 0.13f), RoundedCornerShape(50))
            .padding(horizontal = 9.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp)
    ) {
        IconArt(icon, tint = Color(0xFFD3B2FF), size = 12.dp)
        Text(label, color = Color(0xFFD6C4EB), fontSize = 8.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun EnergyShieldMark(modifier: Modifier = Modifier) {
    Canvas(modifier) {
        val sx = size.width / 36f
        val sy = size.height / 40f
        val shield = Path().apply {
            moveTo(18f * sx, 2f * sy)
            lineTo(32f * sx, 7f * sy)
            lineTo(30f * sx, 23f * sy)
            cubicTo(28f * sx, 31f * sy, 22f * sx, 36f * sy, 18f * sx, 38f * sy)
            cubicTo(14f * sx, 36f * sy, 8f * sx, 31f * sy, 6f * sx, 23f * sy)
            lineTo(4f * sx, 7f * sy)
            close()
        }
        drawPath(shield, Brush.linearGradient(listOf(Color(0xFFEBD8FF), Color(0xFF9C60EF))))
        drawPath(shield, Color.White.copy(alpha = 0.75f), style = Stroke(width = 1.2f * sx))
        val check = Path().apply {
            moveTo(11f * sx, 20f * sy); lineTo(16f * sx, 25f * sy); lineTo(26f * sx, 14f * sy)
        }
        drawPath(check, Color(0xFF32134D), style = Stroke(width = 2.7f * sx, cap = StrokeCap.Round, join = StrokeJoin.Round))
        drawLine(Color.White.copy(alpha = 0.42f), Offset(10f * sx, 8f * sy), Offset(18f * sx, 5f * sy),
            strokeWidth = 1.1f * sx, cap = StrokeCap.Round)
    }
}

@Composable
private fun FantasyGuardianIllustration(modifier: Modifier = Modifier) {
    Canvas(modifier) {
        val sx = size.width / 158f
        val sy = size.height / 174f
        fun p(x: Float, y: Float) = Offset(x * sx, y * sy)
        fun sz(w: Float, h: Float) = Size(w * sx, h * sy)
        fun rr(x: Float, y: Float, w: Float, h: Float, radius: Float, color: Color) {
            drawRoundRect(color = color, topLeft = p(x, y), size = sz(w, h),
                cornerRadius = CornerRadius(radius * sx, radius * sy))
        }
        fun gradientRect(x: Float, y: Float, w: Float, h: Float, radius: Float, colors: List<Color>) {
            drawRoundRect(
                brush = Brush.linearGradient(colors, start = p(x, y), end = p(x + w, y + h)),
                topLeft = p(x, y), size = sz(w, h),
                cornerRadius = CornerRadius(radius * sx, radius * sy)
            )
        }

        // Soft energy field and concentric orbital rings.
        val core = p(78f, 76f)
        drawCircle(
            brush = Brush.radialGradient(
                listOf(Color(0xFFE8CFFF).copy(alpha = 0.30f),
                    Color(0xFFB66CFF).copy(alpha = 0.17f),
                    Color(0xFF6D36B2).copy(alpha = 0.045f), Color.Transparent),
                center = core, radius = 91f * sx
            ), radius = 91f * sx, center = core
        )
        val orbitBack = Path().apply {
            moveTo(7f * sx, 91f * sy)
            cubicTo(18f * sx, 19f * sy, 128f * sx, 11f * sy, 151f * sx, 81f * sy)
            cubicTo(139f * sx, 150f * sy, 30f * sx, 160f * sy, 7f * sx, 91f * sy)
        }
        drawPath(orbitBack, Color(0xFFD9B7FF).copy(alpha = 0.25f), style = Stroke(width = 1.15f * sx))
        drawPath(orbitBack, Color(0xFF8D56C8).copy(alpha = 0.16f),
            style = Stroke(width = 4.2f * sx))
        drawCircle(Color(0xFFF4E8FF), radius = 2.4f * sx, center = p(18f, 65f))
        drawCircle(Color(0xFFC38AFF), radius = 2.1f * sx, center = p(137f, 42f))
        drawCircle(Color(0xFF9E6BD5), radius = 1.7f * sx, center = p(143f, 120f))

        // Rear silhouette, lower body and shoulder armour.
        rr(36f, 101f, 86f, 54f, 22f, Color(0xFF29143F))
        gradientRect(39f, 96f, 80f, 57f, 21f,
            listOf(Color(0xFF9A68CB), Color(0xFF593184), Color(0xFF321B50)))
        rr(47f, 108f, 64f, 39f, 14f, Color(0xFF26133C))
        gradientRect(49f, 106f, 60f, 39f, 13f,
            listOf(Color(0xFFDCC6FA), Color(0xFFA77BE0), Color(0xFF6A429B)))
        drawLine(Color.White.copy(alpha = 0.52f), p(59f, 111f), p(98f, 111f),
            strokeWidth = 1.3f * sx, cap = StrokeCap.Round)

        // Side energy fins and their illuminated inner edges.
        gradientRect(20f, 57f, 17f, 39f, 8f,
            listOf(Color(0xFF9A6BD1), Color(0xFF4B286E), Color(0xFF321849)))
        gradientRect(121f, 57f, 17f, 39f, 8f,
            listOf(Color(0xFF9A6BD1), Color(0xFF4B286E), Color(0xFF321849)))
        rr(25f, 64f, 5f, 24f, 3f, Color(0xFFD6B1FF).copy(alpha = 0.68f))
        rr(128f, 64f, 5f, 24f, 3f, Color(0xFFD6B1FF).copy(alpha = 0.68f))

        // Head shell: dark under-shell, metallic outer casing and glass visor.
        rr(30f, 23f, 98f, 91f, 32f, Color(0xFF321A50))
        gradientRect(33f, 18f, 92f, 88f, 31f,
            listOf(Color(0xFFFFF0FF), Color(0xFFDCC2FF), Color(0xFFAC7BEA), Color(0xFF7547B4)))
        drawRoundRect(
            brush = Brush.linearGradient(
                listOf(Color.White.copy(alpha = 0.52f), Color.Transparent, Color(0xFF633B98).copy(alpha = 0.20f)),
                start = p(43f, 22f), end = p(111f, 102f)
            ),
            topLeft = p(39f, 24f), size = sz(80f, 77f),
            cornerRadius = CornerRadius(27f * sx, 27f * sy)
        )
        rr(43f, 38f, 72f, 48f, 21f, Color(0xFF28153E))
        gradientRect(46f, 40f, 66f, 43f, 19f,
            listOf(Color(0xFF43265F), Color(0xFF160D28)))
        drawLine(Color.White.copy(alpha = 0.82f), p(53f, 26f), p(91f, 21f),
            strokeWidth = 2.4f * sx, cap = StrokeCap.Round)
        drawLine(Color(0xFFB88BEA).copy(alpha = 0.45f), p(105f, 32f), p(114f, 43f),
            strokeWidth = 1.1f * sx, cap = StrokeCap.Round)

        // Twin luminous eyes with layered bloom and glass highlights.
        listOf(66f, 94f).forEach { x ->
            drawCircle(Color(0xFFB981FF).copy(alpha = 0.22f), radius = 12f * sx, center = p(x, 61f))
            drawCircle(Color(0xFF9D63E8).copy(alpha = 0.34f), radius = 8f * sx, center = p(x, 61f))
            drawRoundRect(
                brush = Brush.verticalGradient(listOf(Color(0xFFF4DFFF), Color(0xFFB97BFF), Color(0xFF8751D1)),
                    startY = 51f * sy, endY = 72f * sy),
                topLeft = p(x - 4f, 53f), size = sz(8f, 16f),
                cornerRadius = CornerRadius(4f * sx, 4f * sy)
            )
            drawCircle(Color.White.copy(alpha = 0.90f), radius = 1.5f * sx, center = p(x - 1.5f, 56f))
        }

        // Shield is built from a shadow, bevel, face and a glass-like highlight.
        val shield = Path().apply {
            moveTo(79f * sx, 91f * sy)
            lineTo(126f * sx, 105f * sy)
            lineTo(120f * sx, 137f * sy)
            cubicTo(116f * sx, 153f * sy, 94f * sx, 164f * sy, 79f * sx, 170f * sy)
            cubicTo(64f * sx, 164f * sy, 42f * sx, 153f * sy, 38f * sx, 137f * sy)
            lineTo(32f * sx, 105f * sy)
            close()
        }
        val shieldShadow = Path().apply {
            addPath(shield)
            translate(Offset(2.2f * sx, 3.5f * sy))
        }
        drawPath(shieldShadow, Color(0xFF160B27).copy(alpha = 0.78f))
        drawPath(shield, Color(0xFF4B2774))
        drawPath(shield, Brush.linearGradient(
            listOf(Color(0xFFFFEFFF), Color(0xFFE0C5FF), Color(0xFFB47CFF), Color(0xFF713BBE)),
            start = p(43f, 94f), end = p(116f, 166f)
        ))
        drawPath(shield, Color.White.copy(alpha = 0.82f), style = Stroke(width = 1.55f * sx))
        val innerShield = Path().apply {
            moveTo(79f * sx, 97f * sy)
            lineTo(119f * sx, 109f * sy)
            lineTo(114f * sx, 136f * sy)
            cubicTo(110f * sx, 149f * sy, 91f * sx, 159f * sy, 79f * sx, 164f * sy)
            cubicTo(67f * sx, 159f * sy, 48f * sx, 149f * sy, 44f * sx, 136f * sy)
            lineTo(39f * sx, 109f * sy)
            close()
        }
        drawPath(innerShield, Color(0xFF9E65E8).copy(alpha = 0.20f), style = Stroke(width = 1f * sx))
        val facet = Path().apply {
            moveTo(79f * sx, 97f * sy)
            lineTo(119f * sx, 109f * sy)
            lineTo(79f * sx, 123f * sy)
            lineTo(39f * sx, 109f * sy)
            close()
        }
        drawPath(facet, Color.White.copy(alpha = 0.15f))
        drawLine(Color.White.copy(alpha = 0.48f), p(48f, 108f), p(78f, 99f),
            strokeWidth = 1.5f * sx, cap = StrokeCap.Round)
        val check = Path().apply {
            moveTo(59f * sx, 128f * sy)
            lineTo(73f * sx, 141f * sy)
            lineTo(101f * sx, 112f * sy)
        }
        drawPath(check, Color(0xFF7B45C2).copy(alpha = 0.65f),
            style = Stroke(width = 6f * sx, cap = StrokeCap.Round, join = StrokeJoin.Round))
        drawPath(check, Color.White,
            style = Stroke(width = 3.4f * sx, cap = StrokeCap.Round, join = StrokeJoin.Round))

        // Floating crystal spark and small energy particles.
        val sparkle = Path().apply {
            moveTo(143f * sx, 87f * sy)
            lineTo(147f * sx, 97f * sy)
            lineTo(157f * sx, 101f * sy)
            lineTo(147f * sx, 105f * sy)
            lineTo(143f * sx, 115f * sy)
            lineTo(139f * sx, 105f * sy)
            lineTo(129f * sx, 101f * sy)
            lineTo(139f * sx, 97f * sy)
            close()
        }
        drawPath(sparkle, Brush.linearGradient(listOf(Color.White, Color(0xFFC99BFF))))
        drawCircle(Color.White.copy(alpha = 0.86f), radius = 1.7f * sx, center = p(25f, 112f))
        drawCircle(Color(0xFFD6B5FF), radius = 1.3f * sx, center = p(132f, 27f))
    }
}

@Composable
private fun StatusCard(
    modifier: Modifier,
    icon: String,
    title: String,
    value: String,
    detail: String,
    tint: Color
) {
    val shape = RoundedCornerShape(23.dp)
    Card(
        modifier = modifier.border(
            androidx.compose.foundation.BorderStroke(1.dp, tint.copy(alpha = 0.24f)),
            shape
        ),
        shape = shape,
        colors = CardDefaults.cardColors(containerColor = Color(0xFF171027))
    ) {
        Box(
            Modifier
                .fillMaxWidth()
                .background(
                    Brush.linearGradient(
                        listOf(tint.copy(alpha = 0.13f), Color(0xFF211532), Color(0xFF171027))
                    )
                )
                .padding(horizontal = 14.dp, vertical = 15.dp)
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        Modifier
                            .size(38.dp)
                            .background(tint.copy(alpha = 0.14f), RoundedCornerShape(13.dp))
                            .border(1.dp, tint.copy(alpha = 0.20f), RoundedCornerShape(13.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        IconArt(icon, tint = tint, size = 20.dp)
                    }
                    Box(
                        Modifier
                            .size(8.dp)
                            .background(tint, CircleShape)
                    )
                }
                Text(
                    title,
                    color = TextSecondary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    value,
                    color = TextPrimary,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.ExtraBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    detail,
                    color = TextTertiary,
                    fontSize = 10.sp,
                    maxLines = 2,
                    lineHeight = 14.sp
                )
            }
        }
    }
}

@Composable
private fun SectionTitle(
    title: String,
    detail: String,
    action: String? = null,
    onAction: (() -> Unit)? = null
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Bottom
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(3.dp), modifier = Modifier.weight(1f)) {
            Text(title, color = TextPrimary, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Text(detail, color = TextSecondary, fontSize = 11.sp)
        }
        if (action != null && onAction != null) {
            Text(
                action,
                modifier = Modifier.clickable(onClick = onAction).padding(start = 8.dp, top = 6.dp, bottom = 4.dp),
                color = BrandTeal,
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}

@Composable
private fun EyebrowLabel(text: String) {
    Text(
        text,
        color = BrandTeal,
        fontSize = 10.sp,
        letterSpacing = 0.75.sp,
        fontWeight = FontWeight.Bold
    )
}

@Composable
private fun StatusBadge(text: String, tint: Color) {
    Surface(color = tint.copy(alpha = 0.11f), shape = RoundedCornerShape(50)) {
        Text(
            text,
            color = tint,
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 9.dp, vertical = 5.dp)
        )
    }
}

@Composable
private fun RecentScanCard(
    fa: Boolean,
    result: ScanResult,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(19.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Row(
            modifier = Modifier.padding(15.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Box(
                Modifier.size(42.dp).background(BrandBlue.copy(alpha = 0.12f), RoundedCornerShape(13.dp)),
                contentAlignment = Alignment.Center
            ) {
                IconArt("scan_clock", tint = BrandBlue, size = 21.dp)
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(tr(fa, "آخرین گزارش اسکن", "Latest scan report"), color = TextSecondary, fontSize = 10.sp)
                Text(result.displayName, color = TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(verdictTitle(result.verdict, fa), color = verdictColor(result.verdict), fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
            }
            IconArt("chevron", tint = TextTertiary, size = 17.dp)
        }
    }
}

@Composable
private fun QuickActionCard(
    modifier: Modifier,
    icon: String,
    title: String,
    caption: String,
    onClick: () -> Unit
) {
    val shape = RoundedCornerShape(20.dp)
    Card(
        modifier = modifier.border(1.dp, BrandTeal.copy(alpha = 0.15f), shape).clickable(onClick = onClick),
        shape = shape, colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Row(
            modifier = Modifier.background(Brush.linearGradient(
                listOf(Color(0xFF332052).copy(alpha = 0.72f), SurfaceBase)
            )).padding(13.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Box(Modifier.size(41.dp).background(
                Brush.linearGradient(listOf(Color(0xFFB985FF).copy(alpha = 0.24f), BrandBlue.copy(alpha = 0.12f))),
                RoundedCornerShape(13.dp)
            ), contentAlignment = Alignment.Center) {
                IconArt(icon, tint = BrandTeal, size = 21.dp)
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold, maxLines = 1)
                Text(caption, color = TextSecondary, fontSize = 10.sp, maxLines = 1)
            }
        }
    }
}

@Composable
private fun MiniFeatureCard(
    modifier: Modifier,
    icon: String,
    title: String,
    subtitle: String,
    status: String,
    tint: Color
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            IconArt(icon, tint = tint, size = 22.dp)
            Text(title, color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            Text(subtitle, color = TextSecondary, fontSize = 10.sp, maxLines = 2)
            StatusBadge(status, tint)
        }
    }
}

@Composable
private fun StorePromoCard(fa: Boolean, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(21.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceSoft)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Brush.horizontalGradient(listOf(Color(0xFF48236F), Color(0xFF241442))))
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(13.dp)
        ) {
            Box(
                Modifier.size(45.dp).background(BrandTeal.copy(alpha = 0.12f), RoundedCornerShape(14.dp)),
                contentAlignment = Alignment.Center
            ) {
                IconArt("store", tint = BrandTeal, size = 23.dp)
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(tr(fa, "طرح‌های اشتراک و فروشگاه", "Plans & membership"), color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Text(tr(fa, "امکانات FREE، PLUS و FAMILY را ببین", "Explore FREE, PLUS and FAMILY"), color = TextSecondary, fontSize = 10.sp)
            }
            IconArt("chevron", tint = BrandTeal, size = 18.dp)
        }
    }
}

@Composable
private fun DashboardShortcutCard(
    modifier: Modifier = Modifier,
    icon: String,
    label: String,
    onClick: () -> Unit
) {
    Column(
        modifier = modifier
            .clickable(onClick = onClick)
            .background(
                Brush.verticalGradient(
                    listOf(Color(0xFF35165B), Color(0xFF1B102F))
                ),
                RoundedCornerShape(17.dp)
            )
            .border(1.dp, Color(0xFFB77AFF).copy(alpha = 0.24f), RoundedCornerShape(17.dp))
            .padding(horizontal = 4.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        IconArt(icon, tint = Color(0xFFD8B6FF), size = 22.dp)
        Text(
            label,
            color = Color(0xFFE8D8FA),
            fontSize = 9.sp,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun HomeSafetyStatusCard(
    fa: Boolean,
    scanning: Boolean,
    report: FolderScanReport?,
    onOpenScan: () -> Unit
) {
    val hasFindings = (report?.suspiciousCount ?: 0) > 0
    val hasUnknown = (report?.unknownCount ?: 0) > 0
    // Unknown, skipped or truncated work must never be presented as a fully clean scan.
    val hasIncompleteResults = hasUnknown ||
        report?.failures?.isNotEmpty() == true ||
        report?.truncated == true ||
        (report?.skippedFiles ?: 0) > 0
    val accent = when {
        hasFindings -> ColorDanger
        scanning || report == null || hasIncompleteResults -> ColorWarning
        else -> ColorSuccess
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpenScan)
            .border(1.dp, accent.copy(alpha = 0.25f), RoundedCornerShape(23.dp)),
        shape = RoundedCornerShape(23.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF211337))
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.horizontalGradient(
                        listOf(accent.copy(alpha = 0.12f), Color(0xFF211337), Color(0xFF1A102C))
                    )
                )
                .padding(horizontal = 17.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(13.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(76.dp)
                    .background(accent.copy(alpha = 0.13f), CircleShape)
                    .border(1.5.dp, accent.copy(alpha = 0.55f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                // Keep the full shield/biohazard mark inside a larger, uncropped status medallion.
                if (hasFindings) {
                    IconArt("biohazard", tint = accent, size = 28.dp)
                } else {
                    HighQualityShieldIcon(tint = accent, size = 56.dp)
                }
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    when {
                        scanning -> tr(fa, "اسکن دستگاه در حال اجراست", "Device scan is running")
                        report == null -> tr(fa, "هنوز اسکن دستگاه انجام نشده", "No device scan yet")
                        hasFindings -> tr(fa, "تهدید یا مورد مشکوک پیدا شد", "Threat or suspicious item found")
                        hasIncompleteResults -> tr(fa, "بعضی فایل‌ها نتیجه قطعی ندارند یا کامل اسکن نشدند", "Some files have no definitive verdict or were not fully scanned")
                        else -> tr(fa, "در محدوده اسکن‌شده مورد مشکوکی پیدا نشد", "No suspicious item found in the scanned scope")
                    },
                    color = accent,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.ExtraBold
                )
                Text(
                    when {
                        scanning -> tr(fa, "برای مشاهده جزئیات به مرکز اسکن برو", "Open the scan center for live details")
                        report == null -> tr(fa, "برای بررسی فایل‌های قابل‌دسترسی اسکن را شروع کن", "Start a scan to inspect accessible files")
                        else -> tr(
                            fa,
                            "${report.scannedCount} مورد بررسی • ${report.suspiciousCount} مشکوک • ${report.unknownCount} نامشخص",
                            "${report.scannedCount} scanned • ${report.suspiciousCount} suspicious • ${report.unknownCount} unknown"
                        )
                    },
                    color = TextSecondary,
                    fontSize = 10.sp,
                    lineHeight = 15.sp
                )
            }
            IconArt("chevron", tint = accent, size = 18.dp)
        }
    }
}

@Composable
private fun NeonProgressRing(progress: Float, modifier: Modifier = Modifier) {
    val bounded = progress.coerceIn(0f, 1f)
    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val stroke = size.minDimension * 0.085f
            val inset = stroke / 2f
            val arcSize = androidx.compose.ui.geometry.Size(
                size.width - stroke,
                size.height - stroke
            )
            drawArc(
                color = Color(0xFF7136B5).copy(alpha = 0.48f),
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                topLeft = Offset(inset, inset),
                size = arcSize,
                style = Stroke(width = stroke, cap = StrokeCap.Round)
            )
            drawArc(
                brush = Brush.sweepGradient(
                    listOf(Color(0xFFE8C9FF), Color(0xFFB66CFF), Color(0xFF8B39F5), Color(0xFFE8C9FF))
                ),
                startAngle = -90f,
                sweepAngle = 360f * bounded,
                useCenter = false,
                topLeft = Offset(inset, inset),
                size = arcSize,
                style = Stroke(width = stroke, cap = StrokeCap.Round)
            )
            drawCircle(
                color = Color(0xFFC99AFF).copy(alpha = 0.08f),
                radius = size.minDimension * 0.30f
            )
        }
        EnergyShieldMark(Modifier.size(35.dp))
    }
}

@Composable
private fun ScanCenterScreen(
    fa: Boolean,
    scanning: Boolean,
    result: ScanResult?,
    batchReport: FolderScanReport?,
    batchProgress: String?,
    scanProgress: Float,
    scanCurrent: Int,
    scanTotal: Int,
    scanElapsedMs: Long,
    deviceScanDeep: Boolean,
    errorMessage: String?,
    notice: String?,
    quarantining: Boolean,
    onFileScan: () -> Unit,
    onApkScan: () -> Unit,
    onSelectBatchItem: (FolderScanItem) -> Unit,
    onQuarantine: () -> Unit,
    onClearReport: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(15.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            EyebrowLabel(tr(fa, "تحلیل محلی", "ON-DEVICE ANALYSIS"))
            Text(tr(fa, "مرکز اسکن", "Scan center"), color = TextPrimary, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            Text(
                tr(fa, "بدون انتخاب پوشه؛ اسکن سریع یا عمیق را انتخاب کن تا فایل‌های قابل‌دسترسی خودکار بررسی شوند.", "No folder picker. Choose quick or deep scan to inspect accessible device storage automatically."),
                color = TextSecondary,
                fontSize = 12.sp
            )
        }

        ScanModeCard(
            icon = "file",
            title = tr(fa, "اسکن سریع", "Quick scan"),
            description = tr(fa, "برنامه‌های نصب‌شده و مسیرهای مهم حافظه بررسی می‌شوند؛ این حالت حداکثر ۳۵۰ فایل و ۱ گیگابایت داده را با سقف ۲۰۰ مگابایت برای هر فایل پوشش می‌دهد.", "Checks installed-app packages and key storage folders, up to 350 files and 1 GB total, with a 200 MB per-file limit."),
            tag = tr(fa, "قابل استفاده", "AVAILABLE"),
            enabled = !scanning,
            onClick = onFileScan
        )
        ScanModeCard(
            icon = "apk",
            title = tr(fa, "اسکن عمیق", "Deep scan"),
            description = tr(fa, "حافظه اشتراکیِ قابل‌دسترسی، فایل‌های پنهانِ قابل‌خواندن و APKهای نصب‌شده بررسی می‌شوند؛ سقف اسکن ۱۰٬۰۰۰ فایل، ۵ گیگابایت داده و ۲۰۰ مگابایت برای هر فایل است.", "Checks accessible shared storage, readable hidden files and installed-app APK archives, up to 10,000 files and 5 GB total, with a 200 MB per-file limit."),
            tag = tr(fa, "قابل استفاده", "AVAILABLE"),
            enabled = !scanning,
            onClick = onApkScan
        )
        InfoBanner(
            title = tr(fa, "محدودیت واقعی Android", "Android access boundary"),
            body = tr(
                fa,
                "برای اسکن خودکار باید اجازه «مدیریت همه فایل‌ها» را در تنظیمات فعال کنی. حتی با این اجازه، Android داده خصوصی برنامه‌های دیگر و پوشه‌های Android/data و Android/obb را در اختیار این برنامه نمی‌گذارد.",
                "Automatic scanning requires All files access in Android settings. Even then, Android blocks other apps' private data and the Android/data and Android/obb directories."
            ),
            warning = true
        )

        if (scanning) {
            Card(
                colors = CardDefaults.cardColors(containerColor = SurfaceBase),
                shape = RoundedCornerShape(18.dp)
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(11.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(9.dp)) {
                        IconArt("scan", tint = BrandTeal, size = 19.dp)
                        Text(tr(fa, "در حال اسکن حافظه دستگاه…", "Scanning device storage…"), color = TextPrimary, fontWeight = FontWeight.SemiBold)
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(18.dp)
                    ) {
                        NeonProgressRing(progress = scanProgress, modifier = Modifier.size(116.dp))
                        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                            Text(
                                tr(fa, "تحلیل زنده فایل‌ها", "LIVE FILE ANALYSIS"),
                                color = BrandTeal,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 0.7.sp
                            )
                            Text(
                                "${(scanProgress * 100).toInt()}٪",
                                color = TextPrimary,
                                fontSize = 29.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                batchProgress ?: tr(fa, "فایل‌ها و APKها بدون نصب یا اجرا بررسی می‌شوند.", "Files and APKs are inspected without installation or execution."),
                                color = TextSecondary,
                                fontSize = 10.sp,
                                lineHeight = 15.sp,
                                maxLines = 3,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(9.dp)
                    ) {
                        LiveScanMetric(
                            modifier = Modifier.weight(1f),
                            label = tr(fa, "موارد بررسی‌شده", "Items checked"),
                            value = "$scanCurrent / $scanTotal"
                        )
                        LiveScanMetric(
                            modifier = Modifier.weight(1f),
                            label = tr(fa, "زمان سپری‌شده", "Elapsed time"),
                            value = formatScanDuration(scanElapsedMs)
                        )
                    }
                }
            }
        }

        errorMessage?.let {
            InfoBanner(tr(fa, "اسکن انجام نشد", "Scan failed"), it, warning = true)
        }
        notice?.let {
            InfoBanner(tr(fa, "وضعیت قرنطینه", "Quarantine status"), it, warning = false)
        }

        batchReport?.let { report ->
            BatchScanSummaryCard(
                report = report,
                fa = fa,
                deep = deviceScanDeep,
                onSelect = onSelectBatchItem
            )
        }

        result?.let {
            ScanResultCard(
                result = it,
                fa = fa,
                quarantining = quarantining,
                onQuarantine = onQuarantine,
                onClear = onClearReport
            )
        }

        if (result == null && batchReport == null && errorMessage == null) {
            InfoBanner(
                title = tr(fa, "پیش از شروع", "Before you start"),
                body = tr(
                    fa,
                    "فقط فایل‌های متعلق به خودت یا فایل‌هایی را که اجازه بررسی‌شان را داری انتخاب کن. موتور فعلی هنوز بانک امضای بدافزار تولیدی ندارد.",
                    "Select only files you own or are authorized to inspect. The current engine does not yet contain a production malware-signature database."
                ),
                warning = false
            )
        }
    }
}

@Composable
private fun ScanPictureInPicturePreview(
    fa: Boolean,
    progress: Float,
    current: Int,
    total: Int,
    scanning: Boolean
) {
    val transition = rememberInfiniteTransition(label = "scan-pip-beam")
    val beamPosition by transition.animateFloat(
        initialValue = if (scanning) -0.08f else 0.5f,
        targetValue = if (scanning) 1.08f else 0.5f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1550, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "scan-pip-beam-position"
    )
    val percent = (progress.coerceIn(0f, 1f) * 100f).toInt()
    Box(
        modifier = Modifier.fillMaxSize().clip(RoundedCornerShape(19.dp))
            .background(Brush.horizontalGradient(
                listOf(Color(0xFF170D2A), Color(0xFF2B1745), Color(0xFF120B20))
            ))
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val w = size.width
            val h = size.height
            drawCircle(
                brush = Brush.radialGradient(
                    listOf(Color(0xFFB777FF).copy(alpha = 0.30f), Color.Transparent),
                    center = Offset(w * 0.82f, h * 0.48f), radius = h * 0.92f
                ),
                radius = h * 0.92f, center = Offset(w * 0.82f, h * 0.48f)
            )
            drawRoundRect(
                color = Color(0xFFE7C9FF).copy(alpha = 0.08f),
                topLeft = Offset(w * 0.04f, h * 0.10f),
                size = Size(w * 0.92f, h * 0.80f),
                cornerRadius = CornerRadius(18.dp.toPx())
            )
        }
        Image(
            painter = painterResource(id = R.drawable.guardian_robot),
            contentDescription = tr(fa, "دکتر هوش مصنوعی در حال اسکن", "AI doctor scanning"),
            contentScale = ContentScale.Fit,
            modifier = Modifier.align(Alignment.CenterEnd)
                .fillMaxHeight(0.94f).width(116.dp).alpha(0.96f)
        )
        if (scanning) {
            Canvas(Modifier.fillMaxSize()) {
                val beamY = size.height * beamPosition
                val beamHalfHeight = 13.dp.toPx()
                val imageZoneLeft = size.width * 0.58f
                drawRect(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color.Transparent,
                            Color(0xFFC99AFF).copy(alpha = 0.08f),
                            Color(0xFFF0DFFF).copy(alpha = 0.62f),
                            Color(0xFFB66CFF).copy(alpha = 0.18f),
                            Color.Transparent
                        ),
                        startY = beamY - beamHalfHeight, endY = beamY + beamHalfHeight
                    ),
                    topLeft = Offset(imageZoneLeft, beamY - beamHalfHeight),
                    size = Size(size.width - imageZoneLeft, beamHalfHeight * 2f)
                )
                drawLine(
                    color = Color(0xFFEBD7FF).copy(alpha = 0.74f),
                    start = Offset(imageZoneLeft, beamY), end = Offset(size.width, beamY),
                    strokeWidth = 1.2.dp.toPx()
                )
            }
        }
        Column(
            modifier = Modifier.align(Alignment.CenterStart).fillMaxWidth(0.68f)
                .padding(start = 13.dp, end = 5.dp, top = 9.dp, bottom = 9.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                Box(Modifier.size(7.dp).background(if (scanning) BrandTeal else ColorSuccess, CircleShape))
                Text(
                    tr(fa, if (scanning) "اسکن زنده" else "اسکن تکمیل شد", if (scanning) "LIVE SCAN" else "SCAN COMPLETE"),
                    color = if (scanning) BrandTeal else ColorSuccess,
                    fontSize = 9.sp, fontWeight = FontWeight.ExtraBold, letterSpacing = 0.8.sp
                )
            }
            Text(
                tr(fa, if (scanning) "دکتر در حال بررسی است" else "بررسی به پایان رسید",
                    if (scanning) "Doctor is scanning" else "Scan is complete"),
                color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text("$percent%", color = Color(0xFFE7CCFF), fontSize = 24.sp, fontWeight = FontWeight.ExtraBold)
            Text(if (total > 0) "$current / $total" else tr(fa, "آماده‌سازی…", "Preparing…"),
                color = TextSecondary, fontSize = 9.sp, fontWeight = FontWeight.Medium)
            LinearProgressIndicator(
                progress = { progress.coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth().height(4.dp).clip(CircleShape),
                color = BrandTeal, trackColor = Color(0xFF593B76)
            )
        }
    }
}

@Composable
private fun LiveScanMetric(modifier: Modifier = Modifier, label: String, value: String) {
    Column(
        modifier = modifier
            .background(Color(0xFF160D27), RoundedCornerShape(13.dp))
            .border(1.dp, Color(0xFFB77AFF).copy(alpha = 0.16f), RoundedCornerShape(13.dp))
            .padding(horizontal = 11.dp, vertical = 9.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(label, color = TextTertiary, fontSize = 9.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(value, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Bold)
    }
}

private fun formatScanDuration(durationMs: Long): String {
    val totalSeconds = (durationMs / 1000L).coerceAtLeast(0L)
    val hours = totalSeconds / 3600L
    val minutes = (totalSeconds % 3600L) / 60L
    val seconds = totalSeconds % 60L
    return if (hours > 0L) {
        "%02d:%02d:%02d".format(hours, minutes, seconds)
    } else {
        "%02d:%02d".format(minutes, seconds)
    }
}

@Composable
private fun BatchScanSummaryCard(
    report: FolderScanReport,
    fa: Boolean,
    deep: Boolean,
    onSelect: (FolderScanItem) -> Unit
) {
    var showAllResults by remember { mutableStateOf(false) }
    val importantItems = report.items.filter { item ->
        item.result.verdict in setOf(ScanVerdict.KNOWN_MALWARE, ScanVerdict.POTENTIALLY_UNWANTED, ScanVerdict.SUSPICIOUS)
    }
    val visibleItems = importantItems.take(if (showAllResults) 60 else 8)
    Card(shape = RoundedCornerShape(21.dp), colors = CardDefaults.cardColors(containerColor = SurfaceBase)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(11.dp)) {
            Text(if (deep) tr(fa, "نتیجه اسکن عمیق", "Deep scan results") else tr(fa, "نتیجه اسکن سریع", "Quick scan results"), color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                MetricMini(Modifier.weight(1f), tr(fa, "بررسی‌شده", "Scanned"), report.scannedCount.toString())
                MetricMini(Modifier.weight(1f), tr(fa, "تهدید مهم", "Priority threats"), importantItems.size.toString())
            }
            Text(tr(fa, "از " + report.discoveredFiles + " مورد قابل بررسی، " + report.scannedCount + " مورد اسکن شدند.", report.scannedCount.toString() + " of " + report.discoveredFiles + " discovered items were scanned."), color = TextSecondary, fontSize = 11.sp)
            if (importantItems.isEmpty()) {
                Text(tr(fa, "تهدید تأییدشده یا مورد مشکوک مهمی در نتایج این اسکن پیدا نشد. این نتیجه تضمین پاک‌بودن همه فایل‌ها نیست.", "No confirmed threat or high-priority suspicious item was found. This does not guarantee every file is clean."), color = ColorSuccess, fontSize = 12.sp)
            }
            visibleItems.forEach { item ->
                Row(modifier = Modifier.fillMaxWidth().clickable { onSelect(item) }.padding(vertical = 7.dp), horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconArt("file", tint = verdictColor(item.result.verdict), size = 19.dp)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(item.result.displayName, color = TextPrimary, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(verdictTitle(item.result.verdict, fa), color = verdictColor(item.result.verdict), fontSize = 10.sp)
                    }
                    StatusBadge(verdictBadge(item.result.verdict, fa), verdictColor(item.result.verdict))
                }
            }
            val secondaryCount = report.items.size - importantItems.size + report.failures.size
            if (secondaryCount > 0) {
                Text(text = if (showAllResults) tr(fa, "بستن جزئیات فایل‌ها و موارد بررسی‌نشده", "Hide file and skipped-item details") else tr(fa, "نمایش همه فایل‌ها و موارد نامشخص (" + secondaryCount + ")", "Show all files and unknown/skipped items (" + secondaryCount + ")"), modifier = Modifier.fillMaxWidth().clickable { showAllResults = !showAllResults }.padding(vertical = 9.dp), color = BrandTeal, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            }
            if (showAllResults) {
                report.items.filter { item -> item !in importantItems }.take(60).forEach { item ->
                    Row(modifier = Modifier.fillMaxWidth().clickable { onSelect(item) }.padding(vertical = 6.dp), horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                        IconArt("file", tint = verdictColor(item.result.verdict), size = 17.dp)
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(item.result.displayName, color = TextSecondary, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(verdictTitle(item.result.verdict, fa), color = verdictColor(item.result.verdict), fontSize = 9.sp)
                        }
                        StatusBadge(verdictBadge(item.result.verdict, fa), verdictColor(item.result.verdict))
                    }
                }
                if (report.failures.isNotEmpty()) {
                    Text(tr(fa, "مواردی که اسکن نشدند: " + report.failures.size, "Items that could not be scanned: " + report.failures.size), color = ColorWarning, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                    report.failures.take(30).forEach { failure -> Text(failure.name + ": " + failure.reason, color = TextSecondary, fontSize = 10.sp) }
                }
            }
            if (report.truncated || report.skippedFiles > 0) {
                Text(tr(fa, "محدودیت ایمنی اسکن اعمال شد. موارد ردشده: " + report.skippedFiles, "Safety scan limits were applied. Skipped: " + report.skippedFiles), color = ColorWarning, fontSize = 10.sp)
            }
        }
    }
}
@Composable
private fun ScanModeCard(
    icon: String,
    title: String,
    description: String,
    tag: String,
    enabled: Boolean,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (enabled) Modifier.clickable(onClick = onClick) else Modifier),
        shape = RoundedCornerShape(19.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (enabled) SurfaceBase else SurfaceBase.copy(alpha = 0.65f)
        )
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(13.dp),
            verticalAlignment = Alignment.Top
        ) {
            Box(
                modifier = Modifier
                    .size(45.dp)
                    .background(
                        if (enabled) BrandTeal.copy(alpha = 0.11f) else TextTertiary.copy(alpha = 0.10f),
                        RoundedCornerShape(14.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {
                IconArt(icon, tint = if (enabled) BrandTeal else TextTertiary, size = 22.dp)
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                Text(title, color = if (enabled) TextPrimary else TextSecondary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                Text(description, color = TextSecondary, fontSize = 11.sp, lineHeight = 17.sp)
                StatusBadge(tag, if (enabled) BrandTeal else ColorWarning)
            }
            if (enabled) IconArt("chevron", tint = TextTertiary, size = 17.dp)
        }
    }
}

@Composable
private fun ScanResultCard(
    result: ScanResult,
    fa: Boolean,
    quarantining: Boolean,
    onQuarantine: () -> Unit,
    onClear: () -> Unit
) {
    Card(
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Column(Modifier.padding(17.dp), verticalArrangement = Arrangement.spacedBy(13.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(tr(fa, "گزارش تحلیل", "Analysis report"), color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                StatusBadge(verdictBadge(result.verdict, fa), verdictColor(result.verdict))
            }
            Text(
                result.displayName,
                color = TextPrimary,
                fontSize = 14.sp,
                fontWeight = FontWeight.SemiBold,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text(verdictTitle(result.verdict, fa), color = verdictColor(result.verdict), fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Text(verdictDescription(result.verdict, fa), color = TextSecondary, fontSize = 11.sp, lineHeight = 17.sp)
            }

            Row(horizontalArrangement = Arrangement.spacedBy(9.dp)) {
                MetricMini(
                    modifier = Modifier.weight(1f),
                    label = tr(fa, "حجم فایل", "File size"),
                    value = formatBytes(result.sizeBytes)
                )
                MetricMini(
                    modifier = Modifier.weight(1f),
                    label = tr(fa, "زمان تحلیل", "Analysis time"),
                    value = "${result.durationMillis} ms"
                )
            }

            DetailPanel(title = "SHA-256", value = result.sha256)
            result.apkMetadata?.let { apk ->
                Card(colors = CardDefaults.cardColors(containerColor = SurfaceRaised), shape = RoundedCornerShape(15.dp)) {
                    Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                        Text(tr(fa, "اطلاعات APK", "APK details"), color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        DetailLine(tr(fa, "شناسه بسته", "Package name"), apk.packageName)
                        DetailLine("Target SDK", apk.targetSdk.toString())
                        DetailLine(tr(fa, "مجوزهای درخواستی", "Requested permissions"), apk.requestedPermissions.size.toString())
                        DetailLine(tr(fa, "اجزای export شده", "Exported components"), apk.exportedComponentCount.toString())
                        apk.signingCertificateSha256?.let { DetailLine("Signer SHA-256", it) }
                    }
                }
            }

            Text(tr(fa, "شواهد بررسی", "Review evidence"), color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            result.evidence.forEach { item ->
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.Top) {
                    Box(
                        Modifier.padding(top = 5.dp).size(7.dp).background(
                            when (item.severity) {
                                EvidenceSeverity.HIGH -> ColorWarning
                                EvidenceSeverity.MEDIUM -> BrandBlue
                                EvidenceSeverity.LOW -> BrandTeal
                                EvidenceSeverity.INFO -> TextTertiary
                            },
                            CircleShape
                        )
                    )
                    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(item.title, color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        Text(item.detail, color = TextSecondary, fontSize = 10.sp, lineHeight = 15.sp)
                    }
                }
            }

            if (result.verdict in setOf(
                    ScanVerdict.KNOWN_MALWARE,
                    ScanVerdict.POTENTIALLY_UNWANTED,
                    ScanVerdict.SUSPICIOUS
                )
            ) {
                Button(
                    onClick = onQuarantine,
                    enabled = !quarantining,
                    modifier = Modifier.fillMaxWidth().height(49.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = BrandTeal, contentColor = AppBackground)
                ) {
                    Text(
                        if (quarantining) tr(fa, "در حال قرنطینه…", "Quarantining…")
                        else tr(fa, "قرنطینه و درخواست حذف فایل", "Quarantine and request source removal"),
                        fontWeight = FontWeight.Bold
                    )
                }
                Text(
                    tr(
                        fa,
                        "پس از تأیید تو، نسخه رمزنگاری‌شده ابتدا ذخیره و هش آن بررسی می‌شود؛ سپس حذف فایل اصلی از Android درخواست می‌شود. ممکن است ارائه‌دهنده فایل حذف را رد کند.",
                        "After confirmation, an encrypted copy is stored and hash-verified before Android is asked to remove the original. The provider may refuse deletion."
                    ),
                    color = TextTertiary,
                    fontSize = 10.sp,
                    lineHeight = 15.sp
                )
            } else {
                Text(
                    tr(
                        fa,
                        "برای این نتیجه، عملیات حذف از قرنطینه فعال نیست. فایل‌های ناشناخته، پشتیبانی‌نشده و نشانگر آزمایشی بی‌خطر به‌صورت خودکار حذف نمی‌شوند.",
                        "Source-removal quarantine is disabled for this result. Unknown, unsupported and harmless test-marker files are never automatically removed."
                    ),
                    color = ColorWarning,
                    fontSize = 10.sp,
                    lineHeight = 15.sp
                )
            }
            OutlinedButton(onClick = onClear, modifier = Modifier.fillMaxWidth()) {
                Text(tr(fa, "پاک کردن گزارش از صفحه", "Clear report from screen"))
            }
        }
    }
}

@Composable
private fun MetricMini(modifier: Modifier, label: String, value: String) {
    Surface(modifier = modifier, color = SurfaceRaised, shape = RoundedCornerShape(13.dp)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, color = TextTertiary, fontSize = 10.sp)
            Text(value, color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        }
    }
}

@Composable
private fun DetailPanel(title: String, value: String) {
    Surface(color = SurfaceRaised, shape = RoundedCornerShape(13.dp)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text(title, color = TextTertiary, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            Text(value, color = TextSecondary, fontSize = 10.sp, lineHeight = 15.sp)
        }
    }
}

@Composable
private fun DetailLine(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, color = TextTertiary, fontSize = 10.sp)
        Text(value, color = TextPrimary, fontSize = 11.sp)
    }
}

@Composable
private fun SecurityToolsScreen(
    fa: Boolean,
    result: ScanResult?,
    protectionEnabled: Boolean,
    onToggleProtection: (Boolean) -> Unit,
    onOpenScan: () -> Unit,
    onOpenVault: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var currentFeed by remember { mutableStateOf(ThreatFeedRuntime.currentFeed(context)) }
    var refreshingFeed by remember { mutableStateOf(false) }
    var feedMessage by remember { mutableStateOf<String?>(null) }
    var feedMessageSuccess by remember { mutableStateOf(false) }
    val fileMonitoringAvailable = Build.VERSION.SDK_INT < Build.VERSION_CODES.R ||
        Environment.isExternalStorageManager()
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) onToggleProtection(true)
        else {
            feedMessage = tr(fa, "برای نمایش هشدارهای محافظت، مجوز اعلان لازم است.", "Notification permission is required for visible protection alerts.")
            feedMessageSuccess = false
        }
    }
    val enableProtection = {
        if (Build.VERSION.SDK_INT >= 33 &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            onToggleProtection(true)
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(17.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            EyebrowLabel(tr(fa, "محافظت دستگاه", "DEVICE PROTECTION"))
            Text(tr(fa, "جعبه‌ابزار امنیتی", "Security toolkit"), color = TextPrimary, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            Text(tr(fa, "ابزارهای اصلی در یک‌جا", "Your essential security tools"), color = TextSecondary, fontSize = 12.sp)
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(23.dp),
            colors = CardDefaults.cardColors(containerColor = SurfaceRaised)
        ) {
            Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(11.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    HighQualityShieldIcon(
                        tint = if (protectionEnabled) ColorSuccess else ColorWarning,
                        size = 50.dp
                    )
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(tr(fa, "محافظت بلادرنگ", "Real-time protection"), color = TextPrimary, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Text(
                            if (protectionEnabled) tr(fa, "سرویس محافظت روشن است", "Protection service is running") else tr(fa, "پایش فایل‌ها و برنامه‌های تازه نصب‌شده", "Monitor new files and newly installed apps"),
                            color = if (protectionEnabled) ColorSuccess else TextSecondary,
                            fontSize = 11.sp
                        )
                    }
                    StatusBadge(
                        text = if (protectionEnabled) tr(fa, "فعال", "ON") else tr(fa, "خاموش", "OFF"),
                        tint = if (protectionEnabled) ColorSuccess else ColorWarning
                    )
                }
                Text(
                    tr(fa, "هنگام فعال بودن، فایل‌های تازه در پوشه‌های قابل‌دسترسی و برنامه‌های تازه نصب‌شده بررسی می‌شوند. Android دسترسی به داده‌های خصوصی برنامه‌های دیگر و پایش کامل شبکه را به این سرویس نمی‌دهد.", "When enabled, newly written files in accessible folders and newly installed apps are checked. Android does not expose other apps' private data or a system-wide network inspection API to this service."),
                    color = TextSecondary,
                    fontSize = 10.sp,
                    lineHeight = 15.sp
                )
                if (!fileMonitoringAvailable) {
                    Text(
                        tr(fa, "برای پایش فایل‌های حافظه، مجوز مدیریت همه فایل‌ها را از تنظیمات Android فعال کن. پایش نصب برنامه‌ها مستقل از این مجوز است.", "To monitor shared-storage files, grant All files access in Android settings. App-install monitoring works independently."),
                        color = ColorWarning,
                        fontSize = 10.sp,
                        lineHeight = 15.sp
                    )
                    OutlinedButton(
                        onClick = {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                val settingsIntent = Intent(
                                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                                    Uri.parse("package:${context.packageName}")
                                )
                                runCatching { context.startActivity(settingsIntent) }
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text(tr(fa, "تنظیم دسترسی فایل‌ها", "Set file access")) }
                }
                Button(
                    onClick = { if (protectionEnabled) onToggleProtection(false) else enableProtection() },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (protectionEnabled) ColorDanger.copy(alpha = 0.88f) else BrandBlue
                    )
                ) {
                    Text(
                        if (protectionEnabled) tr(fa, "توقف محافظت", "Stop protection")
                        else tr(fa, "فعال‌سازی محافظت", "Enable protection")
                    )
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(23.dp),
            colors = CardDefaults.cardColors(containerColor = SurfaceRaised)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(17.dp),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    Modifier.size(56.dp).background(Color(0xFF8B42E8).copy(alpha = 0.18f), RoundedCornerShape(17.dp)),
                    contentAlignment = Alignment.Center
                ) { IconArt("scan_clock", tint = Color(0xFFD9B8FF), size = 29.dp) }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text(tr(fa, "شروع اسکن", "Start a scan"), color = TextPrimary, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                    Text(tr(fa, "اسکن سریع، عمیق و بررسی فایل انتخابی", "Quick, deep and selected-file scans"), color = TextSecondary, fontSize = 11.sp)
                }
                IconArt("chevron", tint = BrandTeal, size = 19.dp)
            }
        }

        val feedForDisplay = currentFeed
        Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = SurfaceBase)) {
            Column(Modifier.fillMaxWidth().padding(15.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(9.dp)) {
                    IconArt("database", tint = if (feedForDisplay != null) ColorSuccess else ColorWarning, size = 24.dp)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(tr(fa, "بانک اطلاعات تهدید", "Threat intelligence database"), color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                        Text(
                            if (feedForDisplay != null) tr(fa, "${feedForDisplay.indicators.size} شاخص معتبر · نسخه ${feedForDisplay.version}", "${feedForDisplay.indicators.size} verified indicators · v${feedForDisplay.version}")
                            else tr(fa, "هنوز بانک امضاشده معتبری روی دستگاه نیست", "No verified signed feed is installed yet"),
                            color = TextSecondary,
                            fontSize = 10.sp
                        )
                    }
                }
                Text(
                    tr(fa, "به‌روزرسانی فقط پس از تأیید امضای دیجیتال و اعتبار بانک پذیرفته می‌شود؛ هیچ فایل یا محتوای شخصی برای دریافت بانک ارسال نمی‌شود.", "Updates are accepted only after digital-signature and freshness checks. No personal file or file content is uploaded to retrieve the feed."),
                    color = TextTertiary,
                    fontSize = 10.sp,
                    lineHeight = 15.sp
                )
                Button(
                    enabled = !refreshingFeed,
                    onClick = {
                        scope.launch {
                            refreshingFeed = true
                            feedMessage = null
                            feedMessageSuccess = false
                            try {
                                currentFeed = ThreatFeedRuntime.refresh(context)
                                feedMessage = tr(fa, "بانک تهدید با موفقیت تأیید و به‌روزرسانی شد.", "Threat intelligence was verified and updated.")
                                feedMessageSuccess = true
                            } catch (error: Exception) {
                                feedMessage = error.message ?: tr(fa, "به‌روزرسانی بانک انجام نشد.", "Threat feed refresh failed.")
                            } finally {
                                refreshingFeed = false
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (refreshingFeed) tr(fa, "در حال دریافت و بررسی…", "Downloading and verifying…") else tr(fa, "به‌روزرسانی بانک تهدید", "Update threat database"))
                }
                feedMessage?.let {
                    Text(it, color = if (feedMessageSuccess) ColorSuccess else ColorWarning, fontSize = 10.sp, lineHeight = 15.sp)
                }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(11.dp)) {
            ToolActionTile(
                modifier = Modifier.weight(1f),
                icon = "lock",
                title = tr(fa, "قرنطینه", "Quarantine"),
                subtitle = tr(fa, "مدیریت موارد ذخیره‌شده", "Manage stored items"),
                onClick = onOpenVault
            )
            ToolActionTile(
                modifier = Modifier.weight(1f),
                icon = "shield",
                title = tr(fa, "گزارش اخیر", "Latest report"),
                subtitle = tr(fa, "مشاهده نتیجه اسکن", "Review scan result"),
                onClick = onOpenScan
            )
        }

        if (result != null) {
            RecentScanCard(fa = fa, result = result, onClick = onOpenScan)
        } else {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = SurfaceBase)
            ) {
                Row(Modifier.padding(15.dp), horizontalArrangement = Arrangement.spacedBy(11.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconArt("search", tint = BrandTeal, size = 21.dp)
                    Text(tr(fa, "هنوز گزارشی ثبت نشده است. برای شروع، اسکن را اجرا کن.", "No scan report yet. Start a scan to create one."), color = TextSecondary, fontSize = 11.sp)
                }
            }
        }
    }
}

@Composable
private fun ToolActionTile(
    modifier: Modifier = Modifier,
    icon: String,
    title: String,
    subtitle: String,
    onClick: () -> Unit
) {
    Card(
        modifier = modifier.clickable(onClick = onClick),
        shape = RoundedCornerShape(19.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Column(
            Modifier.fillMaxWidth().padding(15.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Box(
                Modifier.size(42.dp).background(BrandTeal.copy(alpha = 0.12f), RoundedCornerShape(13.dp)),
                contentAlignment = Alignment.Center
            ) { IconArt(icon, tint = BrandTeal, size = 22.dp) }
            Text(title, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Bold)
            Text(subtitle, color = TextSecondary, fontSize = 10.sp, lineHeight = 14.sp)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                IconArt("chevron", tint = TextTertiary, size = 15.dp)
            }
        }
    }
}

@Composable
private fun QuarantineVaultScreen(
    fa: Boolean,
    refreshKey: Int,
    onDelete: (String) -> Unit
) {
    val context = LocalContext.current
    val entries = remember(refreshKey) { QuarantineVault.list(context.applicationContext) }
    var pendingDelete by remember { mutableStateOf<VaultEntry?>(null) }

    Column(verticalArrangement = Arrangement.spacedBy(15.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            EyebrowLabel(tr(fa, "فضای ایمن", "SECURE STORAGE"))
            Text(tr(fa, "قرنطینه", "Quarantine"), color = TextPrimary, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            Text(tr(fa, "فایل‌های قرنطینه‌شده جدا از فایل‌های اصلی نگهداری می‌شوند.", "Quarantined copies are kept separate from their original files."), color = TextSecondary, fontSize = 11.sp)
        }

        Card(shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = SurfaceBase)) {
            Row(Modifier.fillMaxWidth().padding(15.dp), horizontalArrangement = Arrangement.spacedBy(11.dp), verticalAlignment = Alignment.CenterVertically) {
                IconArt("shield_location", tint = BrandTeal, size = 23.dp)
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(tr(fa, "حفاظت از نسخه‌های قرنطینه", "Quarantine protection"), color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    Text(tr(fa, "حذف نسخه قرنطینه فقط با تأیید شما انجام می‌شود.", "Deleting a quarantined copy always requires your confirmation."), color = TextSecondary, fontSize = 10.sp)
                }
            }
        }

        if (entries.isEmpty()) {
            Card(shape = RoundedCornerShape(18.dp), colors = CardDefaults.cardColors(containerColor = SurfaceBase)) {
                Column(Modifier.fillMaxWidth().padding(22.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(9.dp)) {
                    IconArt("status_shield", tint = ColorSuccess, size = 34.dp)
                    Text(tr(fa, "قرنطینه خالی است", "Quarantine is empty"), color = TextPrimary, fontWeight = FontWeight.Bold)
                    Text(tr(fa, "در صورت قرنطینه یک فایل، اطلاعات آن اینجا نمایش داده می‌شود.", "Quarantined items will appear here."), color = TextSecondary, fontSize = 11.sp, textAlign = TextAlign.Center)
                }
            }
        } else {
            entries.forEach { entry ->
                Card(shape = RoundedCornerShape(17.dp), colors = CardDefaults.cardColors(containerColor = SurfaceBase)) {
                    Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(9.dp)) {
                            IconArt("folder", tint = BrandTeal, size = 19.dp)
                            Text(entry.id.take(8), color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            Spacer(Modifier.weight(1f))
                            StatusBadge(tr(fa, "قرنطینه", "QUARANTINED"), ColorSuccess)
                        }
                        Text(tr(fa, "حجم: " + formatBytes(entry.sizeBytes), "Size: " + formatBytes(entry.sizeBytes)), color = TextSecondary, fontSize = 10.sp)
                        Text("SHA-256  " + entry.sha256.take(20) + "…", color = TextTertiary, fontSize = 9.sp)
                        OutlinedButton(onClick = { pendingDelete = entry }, modifier = Modifier.align(Alignment.End)) {
                            Text(tr(fa, "حذف نسخه قرنطینه", "Delete quarantined copy"), color = ColorDanger, fontSize = 10.sp)
                        }
                    }
                }
            }
        }
    }

    pendingDelete?.let { entry ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            containerColor = SurfaceRaised,
            title = { Text(tr(fa, "حذف نسخه قرنطینه؟", "Delete quarantined copy?"), color = TextPrimary) },
            text = { Text(tr(fa, "این کار نسخه رمزنگاری‌شده ذخیره‌شده در قرنطینه را برای همیشه حذف می‌کند. فایل اصلی را بازیابی نمی‌کند.", "This permanently deletes the encrypted quarantine copy. It does not restore or change the original file."), color = TextSecondary) },
            confirmButton = {
                Button(onClick = { onDelete(entry.id); pendingDelete = null }, colors = ButtonDefaults.buttonColors(containerColor = ColorDanger)) {
                    Text(tr(fa, "حذف دائمی", "Delete permanently"), color = AppBackground)
                }
            },
            dismissButton = {
                OutlinedButton(onClick = { pendingDelete = null }) { Text(tr(fa, "انصراف", "Cancel"), color = TextPrimary) }
            }
        )
    }
}

@Composable
private fun StoreScreen(
    fa: Boolean,
    onSelectPlan: (String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(15.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            EyebrowLabel(tr(fa, "طرح‌های عضویت", "MEMBERSHIP"))
            Text(tr(fa, "فروشگاه", "Store"), color = TextPrimary, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            Text(
                tr(fa, "امکانات تکمیلی برای نیازهای مختلف", "Plans for different security needs"),
                color = TextSecondary,
                fontSize = 12.sp
            )
        }

        InfoBanner(
            title = tr(fa, "پرداخت هنوز فعال نیست", "Checkout is not active"),
            body = tr(
                fa,
                "این نسخه کاتالوگ طرح‌ها را نشان می‌دهد. پرداخت Google Play، قیمت‌گذاری منطقه‌ای و مدیریت اشتراک هنوز متصل نشده‌اند؛ هیچ مبلغی دریافت نمی‌شود.",
                "This version displays the plan catalogue only. Google Play Billing, regional pricing and subscription management are not connected. No payment will be taken."
            ),
            warning = true
        )

        PlanCard(
            fa = fa,
            name = "FREE",
            subtitle = tr(fa, "امنیت پایه، بدون هزینه", "Essential protection, no cost"),
            price = tr(fa, "رایگان", "Free"),
            badge = tr(fa, "طرح فعلی", "CURRENT"),
            highlighted = true,
            features = listOf(
                tr(fa, "اسکن سریع انتخابی و تحلیل پایه APK", "Selected-file scan and basic APK analysis"),
                tr(fa, "گزارش شفاف و نمایش شواهد", "Transparent reports and evidence"),
                tr(fa, "ذخیره نسخه رمزنگاری‌شده فایل", "Encrypted private copy"),
                tr(fa, "پردازش محلی بدون آپلود محتوا", "Local processing without content uploads")
            ),
            onSelect = { onSelectPlan("FREE") }
        )
        PlanCard(
            fa = fa,
            name = "PLUS",
            subtitle = tr(fa, "اشتراک ماهانه", "Monthly membership"),
            price = tr(fa, "قیمت هنگام عرضه", "Price at launch"),
            badge = tr(fa, "به‌زودی", "COMING"),
            highlighted = false,
            features = listOf(
                tr(fa, "به‌روزرسانی بانک تهدید پس از انتشار", "Threat-feed updates after launch"),
                tr(fa, "اعتبارسنجی اختیاری هش فایل", "Optional hash reputation"),
                tr(fa, "گزارش‌های امنیتی تکمیلی", "Expanded security reports")
            ),
            onSelect = { onSelectPlan("PLUS MONTHLY") }
        )
        PlanCard(
            fa = fa,
            name = "PLUS ANNUAL",
            subtitle = tr(fa, "اشتراک سالانه", "Annual membership"),
            price = tr(fa, "قیمت هنگام عرضه", "Price at launch"),
            badge = tr(fa, "به‌زودی", "COMING"),
            highlighted = false,
            features = listOf(
                tr(fa, "تمام قابلیت‌های طرح PLUS", "All PLUS features"),
                tr(fa, "مدیریت و بازیابی اشتراک", "Subscription management and restoration"),
                tr(fa, "قیمت‌گذاری منطقه‌ای شفاف", "Transparent regional pricing")
            ),
            onSelect = { onSelectPlan("PLUS ANNUAL") }
        )
        PlanCard(
            fa = fa,
            name = "PRO FAMILY",
            subtitle = tr(fa, "برای چند دستگاه", "For multiple devices"),
            price = tr(fa, "قیمت هنگام عرضه", "Price at launch"),
            badge = tr(fa, "به‌زودی", "COMING"),
            highlighted = false,
            features = listOf(
                tr(fa, "مدیریت چند دستگاه با رضایت کاربران", "Multi-device management with user consent"),
                tr(fa, "نمای کلی امنیت خانواده", "Family security overview"),
                tr(fa, "مدیریت اعضا و اشتراک", "Member and plan management")
            ),
            onSelect = { onSelectPlan("PRO FAMILY") }
        )
        PlanCard(
            fa = fa,
            name = "LIFETIME OFFLINE",
            subtitle = tr(fa, "مجوز یک‌باره برای ابزارهای محلی", "One-time licence for local tools"),
            price = tr(fa, "قیمت هنگام عرضه", "Price at launch"),
            badge = tr(fa, "به‌زودی", "COMING"),
            highlighted = false,
            features = listOf(
                tr(fa, "قابلیت‌های محلی بدون سرویس ابری", "Local features without cloud dependency"),
                tr(fa, "بدون تمدید اشتراک", "No subscription renewal"),
                tr(fa, "به‌روزرسانی امنیتی طبق شرایط عرضه", "Security updates under release terms")
            ),
            onSelect = { onSelectPlan("LIFETIME OFFLINE") }
        )
    }
}

@Composable
private fun PlanCard(
    fa: Boolean,
    name: String,
    subtitle: String,
    price: String,
    badge: String,
    highlighted: Boolean,
    features: List<String>,
    onSelect: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (highlighted) Modifier.border(1.dp, BrandTeal.copy(alpha = 0.58f), RoundedCornerShape(21.dp))
                else Modifier
            ),
        colors = CardDefaults.cardColors(
            containerColor = if (highlighted) Color(0xFF122D39) else SurfaceBase
        ),
        shape = RoundedCornerShape(21.dp)
    ) {
        Column(Modifier.padding(17.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(name, color = TextPrimary, fontSize = 17.sp, fontWeight = FontWeight.ExtraBold)
                    Text(subtitle, color = TextSecondary, fontSize = 11.sp)
                }
                StatusBadge(badge, if (highlighted) BrandTeal else TextTertiary)
            }
            Text(price, color = if (highlighted) BrandTeal else TextPrimary, fontSize = 19.sp, fontWeight = FontWeight.Bold)
            features.forEach { feature ->
                Row(horizontalArrangement = Arrangement.spacedBy(9.dp), verticalAlignment = Alignment.Top) {
                    IconArt("status_check", tint = if (highlighted) BrandTeal else BrandBlue, size = 15.dp)
                    Text(feature, color = TextSecondary, fontSize = 11.sp, lineHeight = 16.sp)
                }
            }
            OutlinedButton(
                onClick = onSelect,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(13.dp),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = if (highlighted) BrandTeal else TextSecondary)
            ) {
                Text(
                    if (highlighted) tr(fa, "طرح فعلی", "Current plan")
                    else tr(fa, "مشاهده جزئیات", "View plan")
                )
            }
        }
    }
}

@Composable
private fun SettingsScreen(
    fa: Boolean,
    onLanguageChange: () -> Unit,
    onPrivacy: () -> Unit,
    onAbout: () -> Unit,
    onFeature: (String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            EyebrowLabel(tr(fa, "شخصی‌سازی", "PREFERENCES"))
            Text(tr(fa, "تنظیمات", "Settings"), color = TextPrimary, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            Text(tr(fa, "کنترل تجربه و اطلاعات برنامه", "Control your app experience and information"), color = TextSecondary, fontSize = 12.sp)
        }
        SettingsRow(
            icon = "globe",
            title = tr(fa, "زبان برنامه", "App language"),
            description = tr(fa, "فارسی / English", "Persian / English"),
            action = if (fa) "EN" else "فا",
            onClick = onLanguageChange
        )
        SettingsRow(
            icon = "lock",
            title = tr(fa, "حریم خصوصی و داده‌ها", "Privacy and data"),
            description = tr(fa, "نحوه استفاده از فایل‌ها و داده‌ها", "How files and data are handled"),
            onClick = onPrivacy
        )
        SettingsRow(
            icon = "info",
            title = tr(fa, "درباره برنامه", "About"),
            description = tr(fa, "نسخه و وضعیت قابلیت‌ها", "Version and feature status"),
            onClick = onAbout
        )
        SettingsRow(
            icon = "shield",
            title = tr(fa, "امنیت و مجوزها", "Security and permissions"),
            description = tr(fa, "محدودیت‌ها و دسترسی‌های نسخه فعلی", "Current app permissions and boundaries"),
            onClick = { onFeature("permissions") }
        )
        SettingsRow(
            icon = "support",
            title = tr(fa, "پشتیبانی", "Support"),
            description = tr(fa, "کانال رسمی پیش از عرضه اضافه می‌شود", "Official channel will be added before launch"),
            onClick = { onFeature("support") }
        )
        InfoBanner(
            title = tr(fa, "نسخه در حال توسعه", "Development build"),
            body = tr(fa, "این نسخه هنوز برای عرضه عمومی یا ادعای محافظت کامل آماده نیست.", "This build is not yet ready for public release or claims of complete protection."),
            warning = true
        )
    }
}

@Composable
private fun SettingsRow(
    icon: String,
    title: String,
    description: String,
    action: String? = null,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(17.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Row(
            modifier = Modifier.padding(15.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                Modifier.size(41.dp).background(BrandTeal.copy(alpha = 0.10f), RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center
            ) {
                IconArt(icon, tint = BrandTeal, size = 20.dp)
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, color = TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                Text(description, color = TextSecondary, fontSize = 10.sp)
            }
            if (action != null) {
                Text(action, color = BrandTeal, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            } else {
                IconArt("chevron", tint = TextTertiary, size = 16.dp)
            }
        }
    }
}

@Composable
private fun InfoBanner(title: String, body: String, warning: Boolean) {
    val tint = if (warning) ColorWarning else BrandBlue
    Card(
        shape = RoundedCornerShape(17.dp),
        colors = CardDefaults.cardColors(containerColor = tint.copy(alpha = 0.075f))
    ) {
        Row(
            modifier = Modifier.padding(15.dp),
            horizontalArrangement = Arrangement.spacedBy(11.dp),
            verticalAlignment = Alignment.Top
        ) {
            IconArt(if (warning) "alert" else "info", tint = tint, size = 19.dp)
            Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text(title, color = TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                Text(body, color = TextSecondary, fontSize = 10.sp, lineHeight = 15.sp)
            }
        }
    }
}

@Composable
private fun HighQualityShieldIcon(tint: Color, size: Dp) {
    Canvas(Modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val shield = Path().apply {
            moveTo(w * 0.5f, h * 0.045f)
            cubicTo(w * 0.67f, h * 0.13f, w * 0.83f, h * 0.19f, w * 0.94f, h * 0.22f)
            lineTo(w * 0.895f, h * 0.57f)
            cubicTo(w * 0.86f, h * 0.78f, w * 0.70f, h * 0.92f, w * 0.5f, h * 0.965f)
            cubicTo(w * 0.30f, h * 0.92f, w * 0.14f, h * 0.78f, w * 0.105f, h * 0.57f)
            lineTo(w * 0.06f, h * 0.22f)
            cubicTo(w * 0.17f, h * 0.19f, w * 0.33f, h * 0.13f, w * 0.5f, h * 0.045f)
            close()
        }
        // Vector glow + gradient fill + crisp outline: no 32px atlas upscaling.
        drawPath(
            shield,
            tint.copy(alpha = 0.14f),
            style = Stroke(width = w * 0.18f, cap = StrokeCap.Round, join = StrokeJoin.Round)
        )
        drawPath(
            shield,
            Brush.linearGradient(
                colors = listOf(tint.copy(alpha = 0.98f), tint.copy(alpha = 0.62f)),
                start = Offset(w * 0.2f, h * 0.05f),
                end = Offset(w * 0.8f, h)
            )
        )
        drawPath(
            shield,
            Color.White.copy(alpha = 0.82f),
            style = Stroke(width = w * 0.035f, cap = StrokeCap.Round, join = StrokeJoin.Round)
        )
        val highlight = Path().apply {
            moveTo(w * 0.22f, h * 0.27f)
            cubicTo(w * 0.34f, h * 0.23f, w * 0.41f, h * 0.19f, w * 0.5f, h * 0.145f)
        }
        drawPath(
            highlight,
            Color.White.copy(alpha = 0.28f),
            style = Stroke(width = w * 0.035f, cap = StrokeCap.Round)
        )
        drawLine(
            Color.White,
            Offset(w * 0.29f, h * 0.51f),
            Offset(w * 0.44f, h * 0.65f),
            strokeWidth = w * 0.09f,
            cap = StrokeCap.Round
        )
        drawLine(
            Color.White,
            Offset(w * 0.44f, h * 0.65f),
            Offset(w * 0.73f, h * 0.35f),
            strokeWidth = w * 0.09f,
            cap = StrokeCap.Round
        )
    }
}
@Composable
private fun AssetArt(index: Int, size: Dp) {
    val atlas = ImageBitmap.imageResource(R.drawable.security_artwork_sheet)
    Canvas(Modifier.size(size)) {
        val cell = 32
        val safeIndex = index.coerceIn(0, 15)
        drawImage(
            image = atlas,
            srcOffset = IntOffset((safeIndex % 4) * cell, (safeIndex / 4) * cell),
            srcSize = IntSize(cell, cell),
            dstSize = IntSize(this.size.width.toInt().coerceAtLeast(1), this.size.height.toInt().coerceAtLeast(1)),
            filterQuality = FilterQuality.High
        )
    }
}

@Composable
private fun IconArt(
    name: String,
    tint: Color,
    size: Dp
) {
    // The current 16-tile artwork atlas is readable but undersized throughout the UI.
    // Render every IconArt asset and fallback glyph at 2x its former dimensions.
    val displaySize = size * 2f
    if (name == "shield" || name == "shield_check" || name == "status_shield") {
        HighQualityShieldIcon(tint = tint, size = displaySize)
        return
    }
    Canvas(Modifier.size(displaySize)) {
        val sx = this.size.width / 24f
        val sy = this.size.height / 24f
        val sw = maxOf(1.45f, this.size.minDimension * 0.075f)
        fun point(x: Float, y: Float) = Offset(x * sx, y * sy)
        fun line(x1: Float, y1: Float, x2: Float, y2: Float) {
            drawLine(tint, point(x1, y1), point(x2, y2), strokeWidth = sw, cap = StrokeCap.Round)
        }
        fun path(block: Path.() -> Unit) {
            val p = Path().apply(block)
            drawPath(p, tint, style = Stroke(width = sw, cap = StrokeCap.Round, join = StrokeJoin.Round))
        }
        fun circle(x: Float, y: Float, r: Float) {
            drawCircle(tint, radius = r * sx, center = point(x, y), style = Stroke(width = sw))
        }
        when (name) {
            "biohazard", "malware" -> {
                // Generic microbial threat mark: vector body, core and radial spikes.
                circle(12f, 12f, 5.8f)
                circle(12f, 12f, 1.8f)
                line(12f, 1.8f, 12f, 5.5f); line(12f, 18.5f, 12f, 22.2f)
                line(1.8f, 12f, 5.5f, 12f); line(18.5f, 12f, 22.2f, 12f)
                line(4.3f, 4.3f, 7f, 7f); line(17f, 17f, 19.7f, 19.7f)
                line(19.7f, 4.3f, 17f, 7f); line(7f, 17f, 4.3f, 19.7f)
                circle(12f, 7.3f, 0.75f); circle(7.7f, 14.5f, 0.75f); circle(16.3f, 14.5f, 0.75f)
            }
            "robot" -> {
                line(12f, 2f, 12f, 4.5f)
                circle(12f, 2f, 1f)
                path {
                    moveTo(5f * sx, 6f * sy)
                    lineTo(19f * sx, 6f * sy)
                    quadraticTo(21f * sx, 6f * sy, 21f * sx, 8f * sy)
                    lineTo(21f * sx, 17f * sy)
                    quadraticTo(21f * sx, 19f * sy, 19f * sx, 19f * sy)
                    lineTo(5f * sx, 19f * sy)
                    quadraticTo(3f * sx, 19f * sy, 3f * sx, 17f * sy)
                    lineTo(3f * sx, 8f * sy)
                    quadraticTo(3f * sx, 6f * sy, 5f * sx, 6f * sy)
                }
                circle(8f, 11f, 1.1f); circle(16f, 11f, 1.1f)
                line(8f, 15f, 16f, 15f)
            }
            "scan_clock" -> {
                line(4f, 8f, 4f, 4f); line(4f, 4f, 8f, 4f)
                line(16f, 4f, 20f, 4f); line(20f, 4f, 20f, 8f)
                line(4f, 16f, 4f, 20f); line(4f, 20f, 8f, 20f)
                line(16f, 20f, 20f, 20f); line(20f, 20f, 20f, 16f)
                circle(12f, 12f, 5.2f)
                line(12f, 8.5f, 12f, 12f); line(12f, 12f, 15f, 13.5f)
            }
            "shield_location" -> {
                path {
                    moveTo(12f * sx, 2f * sy)
                    cubicTo(15f * sx, 3.8f * sy, 18f * sx, 4.6f * sy, 21f * sx, 5.2f * sy)
                    lineTo(20f * sx, 13f * sy)
                    cubicTo(19f * sx, 17.5f * sy, 16f * sx, 20.5f * sy, 12f * sx, 22f * sy)
                    cubicTo(8f * sx, 20.5f * sy, 5f * sx, 17.5f * sy, 4f * sx, 13f * sy)
                    lineTo(3f * sx, 5.2f * sy)
                    close()
                }
                circle(12f, 10f, 2.1f)
                path {
                    moveTo(8f * sx, 12f * sy)
                    lineTo(12f * sx, 17f * sy)
                    lineTo(16f * sx, 12f * sy)
                }
            }
            "shield_lightning" -> {
                path {
                    moveTo(12f * sx, 2f * sy)
                    cubicTo(15f * sx, 3.8f * sy, 18f * sx, 4.6f * sy, 21f * sx, 5.2f * sy)
                    lineTo(20f * sx, 13f * sy)
                    cubicTo(19f * sx, 17.5f * sy, 16f * sx, 20.5f * sy, 12f * sx, 22f * sy)
                    cubicTo(8f * sx, 20.5f * sy, 5f * sx, 17.5f * sy, 4f * sx, 13f * sy)
                    lineTo(3f * sx, 5.2f * sy)
                    close()
                }
                path {
                    moveTo(13.5f * sx, 6f * sy)
                    lineTo(9f * sx, 13f * sy)
                    lineTo(12f * sx, 13f * sy)
                    lineTo(10.5f * sx, 18f * sy)
                    lineTo(16f * sx, 10.5f * sy)
                    lineTo(13f * sx, 10.5f * sy)
                    close()
                }
            }
            "apps" -> {
                // Four crisp app tiles; drawn as vectors rather than a 32px atlas.
                path {
                    moveTo(4f * sx, 4f * sy); lineTo(10f * sx, 4f * sy)
                    lineTo(10f * sx, 10f * sy); lineTo(4f * sx, 10f * sy); close()
                    moveTo(14f * sx, 4f * sy); lineTo(20f * sx, 4f * sy)
                    lineTo(20f * sx, 10f * sy); lineTo(14f * sx, 10f * sy); close()
                    moveTo(4f * sx, 14f * sy); lineTo(10f * sx, 14f * sy)
                    lineTo(10f * sx, 20f * sy); lineTo(4f * sx, 20f * sy); close()
                    moveTo(14f * sx, 14f * sy); lineTo(20f * sx, 14f * sy)
                    lineTo(20f * sx, 20f * sy); lineTo(14f * sx, 20f * sy); close()
                }
            }
            "crown" -> {
                path {
                    moveTo(3f * sx, 7f * sy)
                    lineTo(7f * sx, 11f * sy)
                    lineTo(10f * sx, 4f * sy)
                    lineTo(13f * sx, 11f * sy)
                    lineTo(18f * sx, 5f * sy)
                    lineTo(21f * sx, 7f * sy)
                    lineTo(19f * sx, 18f * sy)
                    lineTo(5f * sx, 18f * sy)
                    close()
                }
                line(6f, 21f, 18f, 21f)
            }
            "folder" -> {
                path {
                    moveTo(2.5f * sx, 6f * sy)
                    lineTo(9f * sx, 6f * sy)
                    lineTo(11f * sx, 8.5f * sy)
                    lineTo(21.5f * sx, 8.5f * sy)
                    lineTo(20f * sx, 19.5f * sy)
                    lineTo(4f * sx, 19.5f * sy)
                    close()
                }
            }
            "lightning" -> {
                path {
                    moveTo(13.5f * sx, 2.5f * sy)
                    lineTo(6.5f * sx, 13f * sy)
                    lineTo(11.5f * sx, 13f * sy)
                    lineTo(10f * sx, 21.5f * sy)
                    lineTo(18f * sx, 10f * sy)
                    lineTo(13f * sx, 10f * sy)
                    close()
                }
            }
            "pause" -> {
                path {
                    moveTo(6f * sx, 4f * sy); lineTo(10f * sx, 4f * sy)
                    lineTo(10f * sx, 20f * sy); lineTo(6f * sx, 20f * sy); close()
                    moveTo(14f * sx, 4f * sy); lineTo(18f * sx, 4f * sy)
                    lineTo(18f * sx, 20f * sy); lineTo(14f * sx, 20f * sy); close()
                }
            }
            "search" -> {
                circle(10f, 10f, 6.5f)
                line(15f, 15f, 21f, 21f)
            }
            "shield" -> {
                path {
                    moveTo(12f * sx, 2.2f * sy)
                    lineTo(20.2f * sx, 5.4f * sy)
                    lineTo(19.4f * sx, 13.5f * sy)
                    quadraticTo(18.7f * sx, 19f * sy, 12f * sx, 22f * sy)
                    quadraticTo(5.3f * sx, 19f * sy, 4.6f * sx, 13.5f * sy)
                    lineTo(3.8f * sx, 5.4f * sy)
                    close()
                }
                line(8.2f, 12.3f, 10.8f, 14.8f)
                line(10.8f, 14.8f, 16.2f, 9.2f)
            }
            "home" -> {
                path {
                    moveTo(3f * sx, 10.5f * sy)
                    lineTo(12f * sx, 3f * sy)
                    lineTo(21f * sx, 10.5f * sy)
                    lineTo(19f * sx, 10.5f * sy)
                    lineTo(19f * sx, 21f * sy)
                    lineTo(5f * sx, 21f * sy)
                    lineTo(5f * sx, 10.5f * sy)
                    close()
                }
                line(9.5f, 21f, 9.5f, 14f)
                line(9.5f, 14f, 14.5f, 14f)
                line(14.5f, 14f, 14.5f, 21f)
            }
            "scan" -> {
                line(4f, 9f, 4f, 4f); line(4f, 4f, 9f, 4f)
                line(15f, 4f, 20f, 4f); line(20f, 4f, 20f, 9f)
                line(20f, 15f, 20f, 20f); line(20f, 20f, 15f, 20f)
                line(9f, 20f, 4f, 20f); line(4f, 20f, 4f, 15f)
                line(7f, 12f, 17f, 12f)
            }
            "tools" -> {
                circle(12f, 12f, 2.3f)
                circle(12f, 4.5f, 2f); circle(12f, 19.5f, 2f)
                circle(4.5f, 12f, 2f); circle(19.5f, 12f, 2f)
                line(12f, 7f, 12f, 9f); line(12f, 15f, 12f, 17f)
                line(7f, 12f, 9f, 12f); line(15f, 12f, 17f, 12f)
            }
            "store" -> {
                // Crisp shopping-bag glyph: a clear store/checkout symbol at launcher-scale UI sizes.
                path {
                    moveTo(5f * sx, 8f * sy)
                    lineTo(19f * sx, 8f * sy)
                    lineTo(20.5f * sx, 21f * sy)
                    lineTo(3.5f * sx, 21f * sy)
                    close()
                }
                path {
                    moveTo(8f * sx, 9f * sy)
                    lineTo(8f * sx, 6.5f * sy)
                    cubicTo(8f * sx, 1.8f * sy, 16f * sx, 1.8f * sy, 16f * sx, 6.5f * sy)
                    lineTo(16f * sx, 9f * sy)
                }
                line(8f, 13f, 16f, 13f)
                line(12f, 11.5f, 12f, 17f)
            }
            "settings" -> {
                circle(12f, 12f, 7.5f)
                circle(12f, 12f, 2.7f)
                line(12f, 1.8f, 12f, 4.2f); line(12f, 19.8f, 12f, 22.2f)
                line(1.8f, 12f, 4.2f, 12f); line(19.8f, 12f, 22.2f, 12f)
                line(4.8f, 4.8f, 6.5f, 6.5f); line(17.5f, 17.5f, 19.2f, 19.2f)
                line(17.5f, 6.5f, 19.2f, 4.8f); line(4.8f, 19.2f, 6.5f, 17.5f)
            }
            "file" -> {
                path {
                    moveTo(6f * sx, 2.8f * sy)
                    lineTo(14.5f * sx, 2.8f * sy)
                    lineTo(19f * sx, 7.3f * sy)
                    lineTo(19f * sx, 21f * sy)
                    lineTo(6f * sx, 21f * sy)
                    close()
                    moveTo(14.5f * sx, 3f * sy)
                    lineTo(14.5f * sx, 7.5f * sy)
                    lineTo(19f * sx, 7.5f * sy)
                }
                line(9f, 12f, 16f, 12f); line(9f, 16f, 16f, 16f)
            }
            "apk", "device" -> {
                path {
                    moveTo(7f * sx, 2.5f * sy)
                    lineTo(17f * sx, 2.5f * sy)
                    quadraticTo(19f * sx, 2.5f * sy, 19f * sx, 4.5f * sy)
                    lineTo(19f * sx, 19.5f * sy)
                    quadraticTo(19f * sx, 21.5f * sy, 17f * sx, 21.5f * sy)
                    lineTo(7f * sx, 21.5f * sy)
                    quadraticTo(5f * sx, 21.5f * sy, 5f * sx, 19.5f * sy)
                    lineTo(5f * sx, 4.5f * sy)
                    quadraticTo(5f * sx, 2.5f * sy, 7f * sx, 2.5f * sy)
                    close()
                }
                line(9f, 6f, 15f, 6f)
                circle(12f, 18.5f, 0.7f)
            }
            "database" -> {
                path {
                    moveTo(4f * sx, 6f * sy)
                    quadraticTo(4f * sx, 2.5f * sy, 12f * sx, 2.5f * sy)
                    quadraticTo(20f * sx, 2.5f * sy, 20f * sx, 6f * sy)
                    lineTo(20f * sx, 18f * sy)
                    quadraticTo(20f * sx, 21.5f * sy, 12f * sx, 21.5f * sy)
                    quadraticTo(4f * sx, 21.5f * sy, 4f * sx, 18f * sy)
                    close()
                }
                path {
                    moveTo(4f * sx, 6f * sy)
                    quadraticTo(4f * sx, 9.5f * sy, 12f * sx, 9.5f * sy)
                    quadraticTo(20f * sx, 9.5f * sy, 20f * sx, 6f * sy)
                }
                path {
                    moveTo(4f * sx, 12f * sy)
                    quadraticTo(4f * sx, 15.5f * sy, 12f * sx, 15.5f * sy)
                    quadraticTo(20f * sx, 15.5f * sy, 20f * sx, 12f * sy)
                }
            }
            "clock" -> {
                circle(12f, 12f, 9f)
                line(12f, 6.5f, 12f, 12f)
                line(12f, 12f, 16f, 14f)
            }
            "lock" -> {
                path {
                    moveTo(5f * sx, 10f * sy)
                    lineTo(19f * sx, 10f * sy)
                    lineTo(19f * sx, 21f * sy)
                    lineTo(5f * sx, 21f * sy)
                    close()
                }
                path {
                    moveTo(8f * sx, 10f * sy)
                    lineTo(8f * sx, 7f * sy)
                    quadraticTo(8f * sx, 3f * sy, 12f * sx, 3f * sy)
                    quadraticTo(16f * sx, 3f * sy, 16f * sx, 7f * sy)
                    lineTo(16f * sx, 10f * sy)
                }
                line(12f, 14f, 12f, 17f)
            }
            "activity" -> {
                path {
                    moveTo(2f * sx, 12f * sy)
                    lineTo(6.5f * sx, 12f * sy)
                    lineTo(9f * sx, 5f * sy)
                    lineTo(13.5f * sx, 19f * sy)
                    lineTo(16.5f * sx, 12f * sy)
                    lineTo(22f * sx, 12f * sy)
                }
            }
            "brain" -> {
                circle(12f, 12f, 2.2f)
                circle(6f, 7f, 2.1f); circle(18f, 7f, 2.1f)
                circle(6f, 17f, 2.1f); circle(18f, 17f, 2.1f)
                line(7.7f, 8.4f, 10.3f, 10.3f); line(16.3f, 8.4f, 13.7f, 10.3f)
                line(7.7f, 15.6f, 10.3f, 13.7f); line(16.3f, 15.6f, 13.7f, 13.7f)
            }
            "link" -> {
                path {
                    moveTo(10f * sx, 14f * sy)
                    lineTo(8f * sx, 16f * sy)
                    quadraticTo(5f * sx, 19f * sy, 2.8f * sx, 16.8f * sy)
                    quadraticTo(0.6f * sx, 14.6f * sy, 3.5f * sx, 11.7f * sy)
                    lineTo(7f * sx, 8.2f * sy)
                    quadraticTo(10f * sx, 5.2f * sy, 13f * sx, 8.2f * sy)
                }
                path {
                    moveTo(14f * sx, 10f * sy)
                    lineTo(16f * sx, 8f * sy)
                    quadraticTo(19f * sx, 5f * sy, 21.2f * sx, 7.2f * sy)
                    quadraticTo(23.4f * sx, 9.4f * sy, 20.5f * sx, 12.3f * sy)
                    lineTo(17f * sx, 15.8f * sy)
                    quadraticTo(14f * sx, 18.8f * sy, 11f * sx, 15.8f * sy)
                }
                line(8.5f, 15.5f, 15.5f, 8.5f)
            }
            "globe" -> {
                circle(12f, 12f, 9f)
                path {
                    moveTo(12f * sx, 3f * sy)
                    quadraticTo(5f * sx, 12f * sy, 12f * sx, 21f * sy)
                    quadraticTo(19f * sx, 12f * sy, 12f * sx, 3f * sy)
                }
                line(3.5f, 9f, 20.5f, 9f); line(3.5f, 15f, 20.5f, 15f)
            }
            "info" -> {
                circle(12f, 12f, 9f)
                line(12f, 10.8f, 12f, 16.5f)
                drawCircle(tint, radius = sw * 0.75f, center = point(12f, 7.3f))
            }
            "alert" -> {
                path {
                    moveTo(12f * sx, 3f * sy)
                    lineTo(22f * sx, 20f * sy)
                    lineTo(2f * sx, 20f * sy)
                    close()
                }
                line(12f, 9f, 12f, 14f)
                drawCircle(tint, radius = sw * 0.7f, center = point(12f, 17f))
            }
            "spark" -> {
                path {
                    moveTo(12f * sx, 2f * sy)
                    quadraticTo(14f * sx, 9f * sy, 22f * sx, 12f * sy)
                    quadraticTo(14f * sx, 14f * sy, 12f * sx, 22f * sy)
                    quadraticTo(10f * sx, 14f * sy, 2f * sx, 12f * sy)
                    quadraticTo(10f * sx, 9f * sy, 12f * sx, 2f * sy)
                    close()
                }
            }
            "check" -> {
                path {
                    moveTo(4f * sx, 12.5f * sy)
                    lineTo(9.5f * sx, 18f * sy)
                    lineTo(20f * sx, 6f * sy)
                }
            }
            "arrow", "chevron" -> {
                if (name == "arrow") {
                    line(3f, 12f, 20f, 12f)
                    line(14f, 6f, 20f, 12f)
                    line(14f, 18f, 20f, 12f)
                } else {
                    line(8f, 4f, 16f, 12f)
                    line(16f, 12f, 8f, 20f)
                }
            }
            "support" -> {
                circle(12f, 12f, 8.5f)
                path {
                    moveTo(7.5f * sx, 12f * sy)
                    quadraticTo(7.5f * sx, 7f * sy, 12f * sx, 7f * sy)
                    quadraticTo(16.5f * sx, 7f * sy, 16.5f * sx, 12f * sy)
                    lineTo(16.5f * sx, 15f * sy)
                    lineTo(14f * sx, 15f * sy)
                    lineTo(14f * sx, 12f * sy)
                }
            }
        }
    }
}

private fun verdictBadge(verdict: ScanVerdict, fa: Boolean): String = when (verdict) {
    ScanVerdict.KNOWN_MALWARE -> tr(fa, "بدافزار شناخته‌شده", "KNOWN MALWARE")
    ScanVerdict.POTENTIALLY_UNWANTED -> tr(fa, "برنامه ناخواسته", "POTENTIALLY UNWANTED")
    ScanVerdict.TEST_MARKER_MATCH -> tr(fa, "آزمایشی", "TEST")
    ScanVerdict.SUSPICIOUS -> tr(fa, "نیازمند بررسی", "REVIEW")
    ScanVerdict.NO_KNOWN_INDICATOR -> tr(fa, "بدون تطبیق", "NO MATCH")
    ScanVerdict.UNKNOWN_APK -> tr(fa, "نامشخص", "UNKNOWN")
    ScanVerdict.UNSUPPORTED_FILE -> tr(fa, "پشتیبانی‌نشده", "UNSUPPORTED")
}

private fun verdictTitle(verdict: ScanVerdict, fa: Boolean): String = when (verdict) {
    ScanVerdict.KNOWN_MALWARE -> tr(fa, "هش با بانک تهدید معتبر تطبیق دارد", "Known malware hash match")
    ScanVerdict.POTENTIALLY_UNWANTED -> tr(fa, "فایل احتمالاً ناخواسته است", "Potentially unwanted file")
    ScanVerdict.TEST_MARKER_MATCH -> tr(fa, "نشانگر آزمایشی بی‌خطر شناسایی شد", "Benign test marker matched")
    ScanVerdict.SUSPICIOUS -> tr(fa, "نیازمند بررسی بیشتر", "Needs further review")
    ScanVerdict.NO_KNOWN_INDICATOR -> tr(fa, "نشانگر شناخته‌شده‌ای پیدا نشد", "No known indicator found")
    ScanVerdict.UNKNOWN_APK -> tr(fa, "نتیجه نامشخص", "Unknown result")
    ScanVerdict.UNSUPPORTED_FILE -> tr(fa, "این نوع فایل پشتیبانی نمی‌شود", "File type not covered")
}

private fun verdictDescription(verdict: ScanVerdict, fa: Boolean): String = when (verdict) {
    ScanVerdict.KNOWN_MALWARE -> tr(fa, "هش دقیق فایل در feed امضاشده و تأییدشده تطبیق دارد. این نتیجه بر پایه اعتبار هش است، نه تحلیل رفتاری.", "The exact file hash matched the authenticated signed feed. This is a hash-reputation result, not behavioral analysis.")
    ScanVerdict.POTENTIALLY_UNWANTED -> tr(fa, "هش فایل در دسته PUA بانک تهدید تطبیق دارد؛ پیش از اقدام، ناشر و کاربرد فایل را بررسی کن.", "The file hash matched a PUA entry in the threat feed; review its publisher and purpose before acting.")
    ScanVerdict.TEST_MARKER_MATCH -> tr(fa, "این فقط فایل آزمایشی بی‌خطر پروژه است؛ بدافزار نیست.", "This is the harmless project test fixture, not malware.")
    ScanVerdict.SUSPICIOUS -> tr(fa, "چند نشانه ایستا دیده شده است. این نتیجه اثبات بدافزار بودن نیست.", "Static indicators were found. This is not proof of malware.")
    ScanVerdict.NO_KNOWN_INDICATOR -> tr(fa, "هیچ نشانگر موجود در نسخه فعلی با فایل تطبیق نکرد. این نتیجه تضمین پاک بودن نیست.", "No indicator in this MVP matched. This does not guarantee that the file is safe.")
    ScanVerdict.UNKNOWN_APK -> tr(fa, "اطلاعات APK قابل خواندن نبود؛ از اعلام پاک بودن خودداری می‌کنیم.", "APK metadata could not be read; the file is not declared clean.")
    ScanVerdict.UNSUPPORTED_FILE -> tr(fa, "موتور فعلی تحلیل محتوایی این قالب را انجام نمی‌دهد؛ نتیجه ناشناخته است.", "The current engine does not perform content-aware analysis for this format; treat it as unknown.")
}

private fun verdictColor(verdict: ScanVerdict): Color = when (verdict) {
    ScanVerdict.KNOWN_MALWARE -> ColorDanger
    ScanVerdict.POTENTIALLY_UNWANTED -> ColorWarning
    ScanVerdict.TEST_MARKER_MATCH -> BrandBlue
    ScanVerdict.SUSPICIOUS -> ColorWarning
    ScanVerdict.NO_KNOWN_INDICATOR -> ColorSuccess
    ScanVerdict.UNKNOWN_APK -> ColorWarning
    ScanVerdict.UNSUPPORTED_FILE -> TextTertiary
}

private fun featureTitle(fa: Boolean, feature: String): String = when (feature) {
    "quarantine" -> tr(fa, "قرنطینه رمزنگاری‌شده", "Encrypted quarantine")
    "vulnerability" -> tr(fa, "تحلیل آسیب‌پذیری APK", "APK vulnerability intelligence")
    "phishing" -> tr(fa, "محافظ فیشینگ و لینک", "Phishing & link shield")
    "network" -> tr(fa, "محافظ شبکه", "Network guard")
    "brain" -> tr(fa, "مغز امنیتی AL AI", "AL AI security brain")
    "selfdefense" -> tr(fa, "دفاع از خود برنامه", "Self-defense engine")
    "permissions" -> tr(fa, "امنیت و مجوزها", "Security and permissions")
    else -> tr(fa, "پشتیبانی", "Support")
}

private fun featureDescription(fa: Boolean, feature: String): String = when (feature) {
    "quarantine" -> tr(fa, "با تأیید کاربر، نسخه AES-GCM در فضای خصوصی ذخیره و هش آن بررسی می‌شود؛ سپس حذف فایل مبدأ فقط در صورت اجازه Android یا ارائه‌دهنده فایل درخواست می‌شود. موتور ذخیره‌سازی فهرست، بازیابی و حذف را پشتیبانی می‌کند، اما صفحه مدیریتی کامل قرنطینه هنوز در رابط کاربری تکمیل نشده است.", "After user confirmation, an AES-GCM encrypted copy is stored in private app storage and its hash is verified. Source deletion is requested only if Android or the document provider allows it. The storage engine supports listing, restore and deletion, but a complete quarantine-management screen is not yet available in the UI.")
    "vulnerability" -> tr(fa, "این ماژول هنوز نتیجه آسیب‌پذیری واقعی تولید نمی‌کند. مرحله بعدی شامل شناسایی SDKها و کتابخانه‌ها و تطبیق آن‌ها با منابع CVE معتبر است.", "This module does not yet produce vulnerability findings. Next steps include SDK and library inventory mapped to trusted CVE sources.")
    "phishing" -> tr(fa, "بررسی URL با فهرست اعتبار و تحلیل دامنه هنوز متصل نشده است. هیچ لینک یا پیامی در پس‌زمینه خوانده نمی‌شود.", "URL reputation and domain analysis are not connected yet. No links or messages are read in the background.")
    "network" -> tr(fa, "محافظ شبکه هنوز فعال نیست. پیاده‌سازی آن به طراحی شفاف DNS/VPN محلی و بررسی سیاست‌های Android و Google Play نیاز دارد.", "Network protection is not active. Implementation requires transparent local DNS/VPN design and Android/Google Play policy review.")
    "brain" -> tr(fa, "فعلاً گزارش بر اساس قواعد محدود و شواهد قابل مشاهده ساخته می‌شود. امتیازدهی چندموتوره و تحلیل AI هنوز به موتور اسکن وصل نشده است.", "Reports currently use limited, visible rules and evidence. Multi-engine scoring and AI reasoning are not yet connected to the scanner.")
    "selfdefense" -> tr(fa, "برنامه از تنظیمات پایه مانند غیرفعال‌بودن cleartext و backup استفاده می‌کند. پایش یکپارچگی زمان اجرا و دفاع در برابر دست‌کاری هنوز نیازمند توسعه و آزمون است.", "The app uses baseline controls such as disabled cleartext traffic and backup. Runtime integrity and anti-tamper monitoring still require implementation and testing.")
    "permissions" -> tr(fa, "اسکن سریع مسیرهای رایج حافظه را بررسی می‌کند. اسکن عمیق با اجازه مدیریت همه فایل‌ها، حافظه اشتراکی و APK برنامه‌های نصب‌شده را بررسی می‌کند؛ داده خصوصی برنامه‌های دیگر، Android/data و Android/obb قابل‌دسترسی نیستند.", "Quick scan checks common storage locations. Deep scan uses user-approved All files access to inspect shared storage and installed-app APKs; other apps’ private data, Android/data and Android/obb remain inaccessible.")
    else -> tr(fa, "کانال پشتیبانی رسمی پیش از عرضه عمومی اضافه می‌شود. در این نسخه نشانی پشتیبانی تأییدشده‌ای تعریف نشده است.", "An official support channel will be added before public release. No verified support address is configured in this build.")
}

private fun tr(fa: Boolean, persian: String, english: String): String =
    if (fa) persian else english

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return "%.1f KB".format(kb)
    return "%.2f MB".format(kb / 1024.0)
}

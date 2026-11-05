package com.antivirusalai

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
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
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
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
import com.antivirusalai.remediation.QuarantineManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

private val AppBackground = Color(0xFF100B1B)
private val SurfaceBase = Color(0xFF1B1428)
private val SurfaceRaised = Color(0xFF251B36)
private val SurfaceSoft = Color(0xFF302343)
private val BrandTeal = Color(0xFFB99AFF)
private val BrandBlue = Color(0xFF8066D8)
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
    SETTINGS("settings")
}

@Composable
fun AntivirusApp() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var language by rememberSaveable { mutableStateOf("fa") }
    var activeTab by rememberSaveable { mutableStateOf(MainTab.HOME.key) }
    var scanning by remember { mutableStateOf(false) }
    var quarantining by remember { mutableStateOf(false) }
    var selectedUri by rememberSaveable { mutableStateOf<Uri?>(null) }
    var scanResult by remember { mutableStateOf<ScanResult?>(null) }
    var batchReport by remember { mutableStateOf<FolderScanReport?>(null) }
    var batchProgress by remember { mutableStateOf<String?>(null) }
    var pendingDeepScan by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var notice by remember { mutableStateOf<String?>(null) }
    var selectedPlan by remember { mutableStateOf<String?>(null) }
    var featureInfo by remember { mutableStateOf<String?>(null) }
    var showPrivacy by remember { mutableStateOf(false) }
    var showStoragePermissionRationale by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }
    val fa = language == "fa"

    val executeDeviceScan: (Boolean) -> Unit = { deep ->
        scanning = true
        selectedUri = null
        scanResult = null
        batchReport = null
        batchProgress = null
        errorMessage = null
        notice = null
        activeTab = MainTab.SCAN.key
        scope.launch {
            try {
                batchReport = DeviceScanEngine.scanDevice(
                    context.applicationContext,
                    deep
                ) { current, total, name ->
                    batchProgress = "$current / $total  •  $name"
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                errorMessage = error.message
                    ?: tr(fa, "اسکن حافظه دستگاه انجام نشد.", "Device scan could not be completed.")
            } finally {
                scanning = false
                batchProgress = null
            }
        }
    }

    val storageSettingsLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (DeviceScanEngine.hasBroadStorageAccess()) {
            executeDeviceScan(pendingDeepScan)
        } else {
            errorMessage = tr(
                fa,
                "دسترسی حافظه فعال نشد؛ برای شروع اسکن باید اجازه مدیریت فایل‌ها را در تنظیمات بدهی.",
                "Storage access was not granted. Allow all-files access in Android settings to start scanning."
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
                    MainNavigationBar(
                        activeTab = activeTab,
                        fa = fa,
                        onSelect = { activeTab = it.key }
                    )
                }
            ) { insets ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.verticalGradient(
                                colors = listOf(Color(0xFF241735), Color(0xFF171022), AppBackground)
                            )
                        )
                        .padding(insets)
                ) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        val glowRadius = size.minDimension * 0.72f
                        drawCircle(
                            color = Color(0xFF9B72FF).copy(alpha = 0.10f),
                            radius = glowRadius,
                            center = Offset(size.width * 0.94f, size.height * 0.08f)
                        )
                        drawCircle(
                            color = Color(0xFF6E4DB8).copy(alpha = 0.075f),
                            radius = glowRadius * 0.82f,
                            center = Offset(size.width * 0.04f, size.height * 0.68f)
                        )
                    }
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
                                onOpenScan = { activeTab = MainTab.SCAN.key },
                                onFileScan = launchFileScan,
                                onApkScan = launchApkScan,
                                onOpenTools = { activeTab = MainTab.TOOLS.key },
                                onOpenStore = { activeTab = MainTab.STORE.key }
                            )

                            MainTab.SCAN.key -> ScanCenterScreen(
                                fa = fa,
                                scanning = scanning,
                                result = scanResult,
                                batchReport = batchReport,
                                batchProgress = batchProgress,
                                errorMessage = errorMessage,
                                notice = notice,
                                quarantining = quarantining,
                                onFileScan = launchFileScan,
                                onApkScan = launchApkScan,
                                onSelectBatchItem = { item ->
                                    selectedUri = item.uri
                                    scanResult = item.result
                                },
                                onQuarantine = {
                                    val uri = selectedUri
                                    val result = scanResult
                                    if (uri != null && result != null && !quarantining) {
                                        quarantining = true
                                        scope.launch {
                                            try {
                                                val receipt = QuarantineManager.saveEncryptedCopy(
                                                    context.applicationContext,
                                                    uri,
                                                    result.sha256
                                                )
                                                notice = tr(
                                                    fa,
                                                    "نسخه رمزنگاری‌شده در فضای خصوصی ذخیره شد. شناسه: ${receipt.id.take(8)}. فایل اصلی بدون تغییر باقی مانده است.",
                                                    "An encrypted copy was saved in private storage. ID: ${receipt.id.take(8)}. The original file remains unchanged."
                                                )
                                            } catch (cancelled: CancellationException) {
                                                throw cancelled
                                            } catch (error: Exception) {
                                                notice = error.message ?: tr(fa, "ذخیره نسخه قرنطینه انجام نشد.", "Quarantine copy failed.")
                                            } finally {
                                                quarantining = false
                                            }
                                        }
                                    }
                                },
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
                                onFeature = { featureInfo = it },
                                onOpenScan = { activeTab = MainTab.SCAN.key }
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
                                "ANTIVIRUS AL AI  •  نسخه آزمایشی \${BuildConfig.VERSION_NAME}",
                                "ANTIVIRUS AL AI  •  DEVELOPMENT BUILD \${BuildConfig.VERSION_NAME}"
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
                        "برای اسکن خودکار، Android باید اجازه «مدیریت همه فایل‌ها» را بدهد. این دسترسی فقط برای بررسی فایل‌های حافظه اشتراکی و APKهای قابل‌دسترسی استفاده می‌شود؛ محتوای فایل‌ها از دستگاه خارج نمی‌شود. Android همچنان پوشه‌های خصوصی برنامه‌های دیگر و Android/data و Android/obb را مسدود می‌کند.",
                        "Automatic scanning needs Android’s All files access. ANTIVIRUS AL AI uses it to inspect accessible shared-storage files and APKs only. File contents stay on this device. Android still blocks other apps’ private folders and Android/data and Android/obb."
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
                OutlinedButton(onClick = { showStoragePermissionRationale = false }) {
                    Text(tr(fa, "انصراف", "Cancel"), color = TextPrimary)
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
                        "برای اسکن خودکار، با اجازه صریح تو فایل‌های قابل‌دسترسی در حافظه اشتراکی دستگاه بررسی می‌شوند. Android همچنان دسترسی به پوشه‌های خصوصی برنامه‌های دیگر و بخش‌هایی مانند Android/data و Android/obb را مسدود می‌کند. محتوای فایل‌ها آپلود نمی‌شود. قرنطینه فقط نسخه رمزنگاری‌شده می‌سازد و فایل اصلی را حذف نمی‌کند.",
                        "With your explicit permission, automatic scans inspect accessible files in shared device storage. Android still blocks other apps' private folders and protected areas such as Android/data and Android/obb. File contents are not uploaded. Quarantine creates an encrypted copy and does not delete the original."
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
                        "نسخه \${BuildConfig.VERSION_NAME} • Android • اسکن محلی و گزارش مبتنی بر شواهد. بانک تهدید تولیدی، محافظت بلادرنگ، پرداخت و چند ابزار امنیتی هنوز در دست توسعه هستند.",
                        "Version \${BuildConfig.VERSION_NAME} • Android • Local scanning and evidence-based reports. Production threat intelligence, real-time protection, billing and several security tools are still under development."
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
                    .size(45.dp)
                    .background(
                        Brush.linearGradient(listOf(BrandTeal, BrandBlue)),
                        RoundedCornerShape(15.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {
                IconArt("shield", tint = AppBackground, size = 27.dp)
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
                    tr(fa, "امنیت دیجیتال با شفافیت", "DIGITAL SECURITY, CLEARLY"),
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
                        size = 21.dp
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
    onOpenScan: () -> Unit,
    onFileScan: () -> Unit,
    onApkScan: () -> Unit,
    onOpenTools: () -> Unit,
    onOpenStore: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(21.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                EyebrowLabel(tr(fa, "نمای کلی دستگاه", "DEVICE OVERVIEW"))
                StatusBadge(
                    text = tr(fa, "نسخه \${BuildConfig.VERSION_NAME}", "VERSION \${BuildConfig.VERSION_NAME}"),
                    tint = TextTertiary
                )
            }
            Text(
                tr(fa, "مرکز امنیت", "Security center"),
                color = TextPrimary,
                fontSize = 26.sp,
                fontWeight = FontWeight.Bold
            )
            Text(
                tr(fa, "وضعیت قابلیت‌های امنیتی در این نسخه", "Security capabilities in this build"),
                color = TextSecondary,
                fontSize = 13.sp
            )
        }

        HeroSecurityCard(
            fa = fa,
            scanning = scanning,
            onScan = onOpenScan,
            onApk = onApkScan
        )

        Column(verticalArrangement = Arrangement.spacedBy(11.dp)) {
            SectionTitle(
                title = tr(fa, "وضعیت محافظت", "Protection status"),
                detail = tr(fa, "واقعیت قابلیت‌ها، نه امتیاز ساختگی", "Implemented capabilities, not a made-up score")
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatusCard(
                    modifier = Modifier.weight(1f),
                    icon = "scan",
                    title = tr(fa, "اسکن دستگاه", "Device scan"),
                    value = tr(fa, "آماده", "Ready"),
                    detail = tr(fa, "حافظه و فایل‌ها", "Selected files & APK"),
                    tint = BrandTeal
                )
                StatusCard(
                    modifier = Modifier.weight(1f),
                    icon = "database",
                    title = tr(fa, "بانک تهدید", "Threat feed"),
                    value = tr(fa, "متصل نیست", "Not connected"),
                    detail = tr(fa, "کلید انتشار تنظیم نشده", "Publisher key not set"),
                    tint = ColorWarning
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatusCard(
                    modifier = Modifier.weight(1f),
                    icon = "activity",
                    title = tr(fa, "محافظت بلادرنگ", "Real-time guard"),
                    value = tr(fa, "غیرفعال", "Inactive"),
                    detail = tr(fa, "هنوز پیاده‌سازی نشده", "Not implemented yet"),
                    tint = ColorDanger
                )
                StatusCard(
                    modifier = Modifier.weight(1f),
                    icon = "lock",
                    title = tr(fa, "حریم خصوصی", "Privacy"),
                    value = tr(fa, "محلی", "On-device"),
                    detail = tr(fa, "بدون آپلود محتوا", "No content upload"),
                    tint = ColorSuccess
                )
            }
        }

        if (result != null) {
            RecentScanCard(
                fa = fa,
                result = result,
                onClick = onOpenScan
            )
        }

        Column(verticalArrangement = Arrangement.spacedBy(11.dp)) {
            SectionTitle(
                title = tr(fa, "شروع سریع", "Quick actions"),
                detail = tr(fa, "میان‌برهای کاربردی", "Frequently used actions")
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                QuickActionCard(
                    modifier = Modifier.weight(1f),
                    icon = "file",
                    title = tr(fa, "اسکن سریع", "Quick scan"),
                    caption = tr(fa, "اسکن خودکار", "Automatic scan"),
                    onClick = onFileScan
                )
                QuickActionCard(
                    modifier = Modifier.weight(1f),
                    icon = "apk",
                    title = tr(fa, "اسکن عمیق", "Deep scan"),
                    caption = tr(fa, "حافظه و برنامه‌ها", "Storage & apps"),
                    onClick = onApkScan
                )
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(11.dp)) {
            SectionTitle(
                title = tr(fa, "جعبه‌ابزار امنیتی", "Security toolkit"),
                detail = tr(fa, "ماژول‌های فعلی و آینده", "Current and planned modules"),
                action = tr(fa, "مشاهده همه", "View all"),
                onAction = onOpenTools
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MiniFeatureCard(
                    modifier = Modifier.weight(1f),
                    icon = "lock",
                    title = tr(fa, "قرنطینه", "Quarantine"),
                    subtitle = tr(fa, "نسخه رمزنگاری‌شده", "Encrypted copy"),
                    status = tr(fa, "پایه‌ای", "Basic"),
                    tint = BrandTeal
                )
                MiniFeatureCard(
                    modifier = Modifier.weight(1f),
                    icon = "shield",
                    title = tr(fa, "آسیب‌پذیری", "Vulnerability"),
                    subtitle = tr(fa, "تحلیل APK", "APK intelligence"),
                    status = tr(fa, "در توسعه", "In progress"),
                    tint = ColorWarning
                )
            }
        }

        StorePromoCard(
            fa = fa,
            onClick = onOpenStore
        )

        InfoBanner(
            title = tr(fa, "گزارش‌دهی شفاف", "Transparent reporting"),
            body = tr(
                fa,
                "اسکن عمیق فایل‌های قابل‌دسترسی حافظه اشتراکی و APK برنامه‌های نصب‌شده را بررسی می‌کند؛ داده خصوصی سایر برنامه‌ها و محافظت بلادرنگ در دسترس نیست. نتیجه «بدون نشانگر شناخته‌شده» تضمین پاک بودن نیست.",
                "Deep scan inspects accessible shared-storage files and installed-app APKs; other apps' private data and real-time protection remain unavailable. “No known indicator” is not a clean guarantee."
            ),
            warning = true
        )
    }
}

@Composable
private fun HeroSecurityCard(
    fa: Boolean,
    scanning: Boolean,
    onScan: () -> Unit,
    onApk: () -> Unit
) {
    Card(
        shape = RoundedCornerShape(27.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceRaised)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.linearGradient(
                        colors = listOf(Color(0xFF173B4A), Color(0xFF172F4A), Color(0xFF1A2942))
                    )
                )
                .padding(19.dp)
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(15.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(7.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(Modifier.size(7.dp).background(BrandTeal, CircleShape))
                        Text(
                            tr(fa, "موتور اسکن محلی آماده", "LOCAL SCAN ENGINE READY"),
                            color = BrandTeal,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 0.35.sp
                        )
                    }
                    IconArt("spark", tint = BrandTeal, size = 21.dp)
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    ShieldEmblem(size = 83.dp)
                    Column(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(7.dp)
                    ) {
                        Text(
                            tr(fa, "امنیت را آگاهانه بررسی کن", "Take control of your security"),
                            color = TextPrimary,
                            fontSize = 20.sp,
                            lineHeight = 27.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            tr(
                                fa,
                                "اسکن سریع و عمیق، فایل‌های قابل‌دسترسی را روی همین دستگاه بررسی می‌کنند.",
                                "Quick and deep scans inspect accessible files locally on this device."
                            ),
                            color = Color(0xFFC1D4E5),
                            fontSize = 12.sp,
                            lineHeight = 18.sp
                        )
                    }
                }

                Button(
                    onClick = onScan,
                    modifier = Modifier.fillMaxWidth().height(51.dp),
                    shape = RoundedCornerShape(15.dp),
                    contentPadding = PaddingValues(horizontal = 15.dp, vertical = 11.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = BrandTeal,
                        contentColor = AppBackground
                    )
                ) {
                    Text(
                        if (scanning) tr(fa, "در حال اسکن…", "Scanning…")
                        else tr(fa, "شروع اسکن سریع", "Start quick scan"),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.width(8.dp))
                    IconArt("arrow", tint = AppBackground, size = 17.dp)
                }

                OutlinedButton(
                    onClick = onApk,
                    modifier = Modifier.fillMaxWidth().height(46.dp),
                    shape = RoundedCornerShape(14.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color.White.copy(alpha = 0.17f)),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary)
                ) {
                    IconArt("apk", tint = BrandTeal, size = 17.dp)
                    Spacer(Modifier.width(8.dp))
                    Text(tr(fa, "اسکن عمیق دستگاه", "Deep device scan"), fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
private fun ShieldEmblem(size: Dp) {
    Box(
        modifier = Modifier.size(size),
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .border(1.dp, BrandTeal.copy(alpha = 0.25f), CircleShape)
                .padding(7.dp)
                .border(1.dp, BrandTeal.copy(alpha = 0.42f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Box(
                modifier = Modifier
                    .size(size * 0.61f)
                    .background(BrandTeal.copy(alpha = 0.10f), RoundedCornerShape(20.dp)),
                contentAlignment = Alignment.Center
            ) {
                IconArt("shield", tint = BrandTeal, size = size * 0.38f)
            }
        }
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
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(19.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 13.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(title, color = TextSecondary, fontSize = 11.sp, fontWeight = FontWeight.Medium)
                Box(Modifier.size(7.dp).background(tint, CircleShape))
            }
            Text(
                value,
                color = TextPrimary,
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
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
                IconArt("clock", tint = BrandBlue, size = 21.dp)
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
    Card(
        modifier = modifier.clickable(onClick = onClick),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Row(
            modifier = Modifier.padding(13.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Box(
                Modifier.size(39.dp).background(BrandTeal.copy(alpha = 0.10f), RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center
            ) {
                IconArt(icon, tint = BrandTeal, size = 20.dp)
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
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
                .background(Brush.horizontalGradient(listOf(Color(0xFF163A46), Color(0xFF1C2D49))))
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
private fun ScanCenterScreen(
    fa: Boolean,
    scanning: Boolean,
    result: ScanResult?,
    batchReport: FolderScanReport?,
    batchProgress: String?,
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
            description = tr(fa, "مسیرهای رایج مثل دانلودها، اسناد، تصاویر و رسانه‌ها سریع بررسی می‌شوند.", "Quickly checks common locations such as Downloads, Documents, photos and media."),
            tag = tr(fa, "قابل استفاده", "AVAILABLE"),
            enabled = !scanning,
            onClick = onFileScan
        )
        ScanModeCard(
            icon = "apk",
            title = tr(fa, "اسکن عمیق", "Deep scan"),
            description = tr(fa, "کل حافظه اشتراکیِ قابل‌دسترسی، فایل‌های پنهانِ قابل‌خواندن و APK برنامه‌های نصب‌شده بررسی می‌شوند.", "Checks accessible shared storage, readable hidden files and installed-app APK archives."),
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
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth(),
                        color = BrandTeal,
                        trackColor = BrandTeal.copy(alpha = 0.13f)
                    )
                    Text(batchProgress ?: tr(fa, "فایل‌ها و APKها بدون نصب یا اجرا بررسی می‌شوند.", "Files and APKs are inspected without installation or execution."), color = TextSecondary, fontSize = 11.sp)
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
private fun BatchScanSummaryCard(
    report: FolderScanReport,
    fa: Boolean,
    onSelect: (FolderScanItem) -> Unit
) {
    Card(
        shape = RoundedCornerShape(21.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(11.dp)) {
            Text(tr(fa, "خلاصه اسکن دستگاه", "Device scan summary"), color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                MetricMini(Modifier.weight(1f), tr(fa, "بررسی‌شده", "Scanned"), report.scannedCount.toString())
                MetricMini(Modifier.weight(1f), tr(fa, "مشکوک", "Suspicious"), report.suspiciousCount.toString())
                MetricMini(Modifier.weight(1f), tr(fa, "نامشخص", "Unknown"), report.unknownCount.toString())
            }
            Text(
                tr(fa, "برای دیدن جزئیات هر نتیجه، روی همان فایل بزن.", "Tap a file below to view its detailed report."),
                color = TextSecondary,
                fontSize = 11.sp
            )
            if (report.items.isEmpty()) {
                Text(
                    tr(fa, "فایل قابل اسکن پیدا نشد.", "No scannable files were found."),
                    color = ColorWarning,
                    fontSize = 12.sp
                )
            }
            report.items.take(60).forEach { item ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSelect(item) }
                        .padding(vertical = 7.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconArt("file", tint = verdictColor(item.result.verdict), size = 19.dp)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(item.result.displayName, color = TextPrimary, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(verdictTitle(item.result.verdict, fa), color = verdictColor(item.result.verdict), fontSize = 10.sp)
                    }
                    StatusBadge(verdictBadge(item.result.verdict, fa), verdictColor(item.result.verdict))
                }
            }
            if (report.items.size > 60) {
                Text(
                    tr(fa, "۶۰ مورد اول نمایش داده شده‌اند؛ ${report.items.size - 60} مورد دیگر هم در گزارش ثبت شده‌اند.", "Showing the first 60 of \${report.items.size} scanned files."),
                    color = TextTertiary,
                    fontSize = 10.sp
                )
            }
            if (report.failures.isNotEmpty()) {
                Text(
                    tr(fa, "مواردی که بررسی نشدند: ${report.failures.size}", "Files or folders not scanned: ${report.failures.size}"),
                    color = ColorWarning,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold
                )
                report.failures.take(5).forEach { failure ->
                    Text("${failure.name}: ${failure.reason}", color = TextSecondary, fontSize = 10.sp)
                }
            }
            if (report.truncated || report.skippedFiles > 0) {
                Text(
                    tr(fa, "محدودیت ایمنی اسکن اعمال شد. موارد ردشده: ${report.skippedFiles}", "Safety scan limits were applied. Skipped: ${report.skippedFiles}"),
                    color = ColorWarning,
                    fontSize = 10.sp
                )
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

            Button(
                onClick = onQuarantine,
                enabled = !quarantining,
                modifier = Modifier.fillMaxWidth().height(49.dp),
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = BrandTeal, contentColor = AppBackground)
            ) {
                Text(
                    if (quarantining) tr(fa, "در حال ذخیره…", "Saving…")
                    else tr(fa, "ذخیره نسخه رمزنگاری‌شده", "Save encrypted copy"),
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                tr(
                    fa,
                    "این عملیات فایل اصلی را حذف یا غیرفعال نمی‌کند؛ فقط یک نسخه رمزنگاری‌شده در فضای خصوصی برنامه می‌سازد.",
                    "This does not delete or disable the original. It creates an encrypted copy in private app storage."
                ),
                color = TextTertiary,
                fontSize = 10.sp,
                lineHeight = 15.sp
            )
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
    onFeature: (String) -> Unit,
    onOpenScan: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(15.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            EyebrowLabel(tr(fa, "ماژول‌های امنیتی", "SECURITY MODULES"))
            Text(tr(fa, "جعبه‌ابزار امنیتی", "Security toolkit"), color = TextPrimary, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            Text(tr(fa, "وضعیت هر قابلیت به‌صورت شفاف مشخص شده است.", "Every module is labelled by its actual implementation status."), color = TextSecondary, fontSize = 12.sp)
        }

        ToolModuleCard(
            icon = "lock",
            title = tr(fa, "قرنطینه رمزنگاری‌شده", "Encrypted quarantine"),
            description = tr(fa, "ذخیره نسخه AES-GCM در فضای خصوصی برنامه و بررسی هش؛ فایل اصلی باقی می‌ماند.", "AES-GCM encrypted copy in private storage with hash verification; the original remains in place."),
            status = tr(fa, "پایه‌ای فعال", "BASIC"),
            tint = BrandTeal,
            onClick = { onFeature("quarantine") }
        )
        ToolModuleCard(
            icon = "shield",
            title = tr(fa, "تحلیل آسیب‌پذیری APK", "APK vulnerability intelligence"),
            description = tr(fa, "نقشه‌برداری SDK و کتابخانه‌ها و تطبیق با پایگاه‌های CVE معتبر؛ هنوز پیاده‌سازی نشده است.", "SDK and library inventory with trusted CVE mapping; not implemented yet."),
            status = tr(fa, "در حال توسعه", "IN DEVELOPMENT"),
            tint = ColorWarning,
            onClick = { onFeature("vulnerability") }
        )
        ToolModuleCard(
            icon = "link",
            title = tr(fa, "محافظ فیشینگ و لینک", "Phishing & link shield"),
            description = tr(fa, "بررسی URL انتخاب‌شده توسط کاربر؛ پایگاه اعتبار و تحلیل دامنه هنوز متصل نشده است.", "User-submitted URL checks; reputation and domain analysis are not connected yet."),
            status = tr(fa, "برنامه‌ریزی‌شده", "PLANNED"),
            tint = TextTertiary,
            onClick = { onFeature("phishing") }
        )
        ToolModuleCard(
            icon = "activity",
            title = tr(fa, "محافظ شبکه", "Network guard"),
            description = tr(fa, "محافظت DNS/VPN محلی پس از بررسی حریم خصوصی و سیاست‌های Android و فروشگاه.", "Local DNS/VPN protection after privacy and Android/store policy review."),
            status = tr(fa, "برنامه‌ریزی‌شده", "PLANNED"),
            tint = TextTertiary,
            onClick = { onFeature("network") }
        )
        ToolModuleCard(
            icon = "brain",
            title = tr(fa, "مغز امنیتی AL AI", "AL AI security brain"),
            description = tr(fa, "تجمیع شواهد و امتیازدهی قابل توضیح؛ فعلاً قواعد محدود اسکنر استفاده می‌شوند.", "Explainable evidence aggregation; current scans still use a limited rule set."),
            status = tr(fa, "هسته اولیه", "FOUNDATION"),
            tint = BrandBlue,
            onClick = { onFeature("brain") }
        )
        ToolModuleCard(
            icon = "shield",
            title = tr(fa, "دفاع از خود برنامه", "Self-defense engine"),
            description = tr(fa, "تنظیمات پایه امن اعمال شده‌اند؛ پایش یکپارچگی زمان اجرا هنوز در دست توسعه است.", "Baseline hardening is present; runtime integrity monitoring is still in development."),
            status = tr(fa, "پایه‌ای", "BASELINE"),
            tint = BrandBlue,
            onClick = { onFeature("selfdefense") }
        )

        if (result != null) {
            RecentScanCard(fa = fa, result = result, onClick = onOpenScan)
        }
    }
}

@Composable
private fun ToolModuleCard(
    icon: String,
    title: String,
    description: String,
    status: String,
    tint: Color,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Row(
            modifier = Modifier.padding(15.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.Top
        ) {
            Box(
                Modifier.size(43.dp).background(tint.copy(alpha = 0.11f), RoundedCornerShape(13.dp)),
                contentAlignment = Alignment.Center
            ) {
                IconArt(icon, tint = tint, size = 21.dp)
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(title, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                Text(description, color = TextSecondary, fontSize = 10.sp, lineHeight = 15.sp)
                StatusBadge(status, tint)
            }
            IconArt("chevron", tint = TextTertiary, size = 16.dp)
        }
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
                    IconArt("check", tint = if (highlighted) BrandTeal else BrandBlue, size = 15.dp)
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
private fun IconArt(
    name: String,
    tint: Color,
    size: Dp
) {
    Canvas(Modifier.size(size)) {
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
                path {
                    moveTo(4f * sx, 8f * sy)
                    lineTo(6f * sx, 4f * sy)
                    lineTo(18f * sx, 4f * sy)
                    lineTo(20f * sx, 8f * sy)
                    lineTo(19f * sx, 21f * sy)
                    lineTo(5f * sx, 21f * sy)
                    close()
                }
                path {
                    moveTo(9f * sx, 9f * sy)
                    quadraticTo(9f * sx, 14f * sy, 12f * sx, 14f * sy)
                    quadraticTo(15f * sx, 14f * sy, 15f * sx, 9f * sy)
                }
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
    ScanVerdict.TEST_MARKER_MATCH -> tr(fa, "آزمایشی", "TEST")
    ScanVerdict.SUSPICIOUS -> tr(fa, "نیازمند بررسی", "REVIEW")
    ScanVerdict.NO_KNOWN_INDICATOR -> tr(fa, "بدون تطبیق", "NO MATCH")
    ScanVerdict.UNKNOWN_APK -> tr(fa, "نامشخص", "UNKNOWN")
    ScanVerdict.UNSUPPORTED_FILE -> tr(fa, "پشتیبانی‌نشده", "UNSUPPORTED")
}

private fun verdictTitle(verdict: ScanVerdict, fa: Boolean): String = when (verdict) {
    ScanVerdict.TEST_MARKER_MATCH -> tr(fa, "نشانگر آزمایشی بی‌خطر شناسایی شد", "Benign test marker matched")
    ScanVerdict.SUSPICIOUS -> tr(fa, "نیازمند بررسی بیشتر", "Needs further review")
    ScanVerdict.NO_KNOWN_INDICATOR -> tr(fa, "نشانگر شناخته‌شده‌ای پیدا نشد", "No known indicator found")
    ScanVerdict.UNKNOWN_APK -> tr(fa, "نتیجه نامشخص", "Unknown result")
    ScanVerdict.UNSUPPORTED_FILE -> tr(fa, "این نوع فایل پشتیبانی نمی‌شود", "File type not covered")
}

private fun verdictDescription(verdict: ScanVerdict, fa: Boolean): String = when (verdict) {
    ScanVerdict.TEST_MARKER_MATCH -> tr(fa, "این فقط فایل آزمایشی بی‌خطر پروژه است؛ بدافزار نیست.", "This is the harmless project test fixture, not malware.")
    ScanVerdict.SUSPICIOUS -> tr(fa, "چند نشانه ایستا دیده شده است. این نتیجه اثبات بدافزار بودن نیست.", "Static indicators were found. This is not proof of malware.")
    ScanVerdict.NO_KNOWN_INDICATOR -> tr(fa, "هیچ نشانگر موجود در نسخه فعلی با فایل تطبیق نکرد. این نتیجه تضمین پاک بودن نیست.", "No indicator in this MVP matched. This does not guarantee that the file is safe.")
    ScanVerdict.UNKNOWN_APK -> tr(fa, "اطلاعات APK قابل خواندن نبود؛ از اعلام پاک بودن خودداری می‌کنیم.", "APK metadata could not be read; the file is not declared clean.")
    ScanVerdict.UNSUPPORTED_FILE -> tr(fa, "موتور فعلی تحلیل محتوایی این قالب را انجام نمی‌دهد؛ نتیجه ناشناخته است.", "The current engine does not perform content-aware analysis for this format; treat it as unknown.")
}

private fun verdictColor(verdict: ScanVerdict): Color = when (verdict) {
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
    "quarantine" -> tr(fa, "با درخواست کاربر یک نسخه AES-GCM رمزنگاری‌شده در فضای خصوصی ذخیره و هش آن بررسی می‌شود. فایل اصلی حذف نمی‌شود. مدیریت، بازیابی و حذف امن نسخه‌های قرنطینه در مرحله بعد تکمیل می‌شود.", "At the user's request, an AES-GCM encrypted copy is stored in private app storage and its hash is verified. The original is not removed. Quarantine listing, restore and secure deletion are planned next.")
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

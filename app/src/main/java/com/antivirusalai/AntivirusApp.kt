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
import androidx.compose.ui.geometry.CornerRadius
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
    var deviceScanDeep by remember { mutableStateOf(false) }
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
        deviceScanDeep = deep
        selectedUri = null
        scanResult = null
        batchReport = null
        batchProgress = tr(
            fa,
            "در حال آماده‌سازی فهرست فایل‌ها و برنامه‌های نصب‌شده…",
            "Preparing the file and installed-app inventory…"
        )
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
                        "نسخه ${BuildConfig.VERSION_NAME} • Android • اسکن محلی و گزارش مبتنی بر شواهد. بانک تهدید تولیدی، محافظت بلادرنگ، پرداخت و چند ابزار امنیتی هنوز در دست توسعه هستند.",
                        "Version ${BuildConfig.VERSION_NAME} • Android • Local scanning and evidence-based reports. Production threat intelligence, real-time protection, billing and several security tools are still under development."
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
                EnergyShieldMark(Modifier.size(29.dp))
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
            onScan = onFileScan,
            onApk = onApkScan
        )

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
                    value = tr(fa, "متصل نیست", "Offline"),
                    detail = tr(fa, "اتصال منتشرکننده تنظیم نشده", "Threat feed not configured"),
                    tint = ColorWarning
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatusCard(
                    modifier = Modifier.weight(1f),
                    icon = "activity",
                    title = tr(fa, "محافظت بلادرنگ", "Real-time guard"),
                    value = tr(fa, "غیرفعال", "Inactive"),
                    detail = tr(fa, "در حال توسعه", "Not implemented yet"),
                    tint = ColorDanger
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

                Row(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .padding(top = 15.dp)
                        .background(Color(0xFF130A24).copy(alpha = 0.70f), RoundedCornerShape(50))
                        .border(1.dp, Color(0xFFD7B4FF).copy(alpha = 0.22f), RoundedCornerShape(50))
                        .padding(horizontal = 13.dp, vertical = 7.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Box(Modifier.size(7.dp).background(Color(0xFF73E1AE), CircleShape))
                    Text(
                        tr(fa, "موتور محلی آماده تحلیل", "ON-DEVICE ENGINE READY"),
                        color = Color(0xFFE7D5FF),
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.35.sp
                    )
                }

                FantasyGuardianIllustration(
                    Modifier
                        .align(Alignment.Center)
                        .padding(top = 13.dp)
                        .size(width = 206.dp, height = 226.dp)
                )

                Text(
                    "AL  /  GUARDIAN",
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = 8.dp),
                    color = Color(0xFFD9B9FF).copy(alpha = 0.72f),
                    fontSize = 8.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.8.sp
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
                    IconArt("spark", tint = Color(0xFF49216E), size = 18.dp)
                    Spacer(Modifier.width(10.dp))
                    Text(
                        if (scanning) tr(fa, "در حال اسکن…", "Scanning…")
                        else tr(fa, "شروع اسکن سریع", "Start quick scan"),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Spacer(Modifier.width(9.dp))
                    IconArt("arrow", tint = Color(0xFF49216E), size = 18.dp)
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
                    IconArt("apk", tint = Color(0xFFC69BFF), size = 17.dp)
                    Spacer(Modifier.width(9.dp))
                    Text(
                        tr(fa, "اسکن عمیق دستگاه", "Deep device scan"),
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
private fun ScanCenterScreen(
    fa: Boolean,
    scanning: Boolean,
    result: ScanResult?,
    batchReport: FolderScanReport?,
    batchProgress: String?,
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
            description = tr(fa, "برنامه‌های نصب‌شده، فایل‌های ریشه حافظه و مسیرهای مهم مثل دانلودها و اسناد بررسی می‌شوند.", "Checks installed-app packages, loose storage-root files, and key folders such as Downloads and Documents."),
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
private fun BatchScanSummaryCard(
    report: FolderScanReport,
    fa: Boolean,
    deep: Boolean,
    onSelect: (FolderScanItem) -> Unit
) {
    Card(
        shape = RoundedCornerShape(21.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceBase)
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(11.dp)) {
            Text(
                if (deep) tr(fa, "نتیجه اسکن عمیق", "Deep scan results")
                else tr(fa, "نتیجه اسکن سریع", "Quick scan results"),
                color = TextPrimary,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                MetricMini(Modifier.weight(1f), tr(fa, "بررسی‌شده", "Scanned"), report.scannedCount.toString())
                MetricMini(Modifier.weight(1f), tr(fa, "مشکوک", "Suspicious"), report.suspiciousCount.toString())
                MetricMini(Modifier.weight(1f), tr(fa, "نامشخص", "Unknown"), report.unknownCount.toString())
            }
            Text(
                tr(
                    fa,
                    "از ${report.discoveredFiles} مورد قابل بررسی، ${report.scannedCount} مورد اسکن شدند. برای دیدن شواهد هر نتیجه، روی همان مورد بزن.",
                    "${report.scannedCount} of ${report.discoveredFiles} discovered items were scanned. Tap an item to inspect its evidence."
                ),
                color = TextSecondary,
                fontSize = 11.sp
            )
            if (report.items.isEmpty()) {
                Text(
                    tr(
                        fa,
                        "در محدوده قابل‌دسترسی این حالت فایلی پیدا نشد. مجوز حافظه و پوشه‌های رایج را بررسی کن؛ برای پوشش گسترده‌تر اسکن عمیق را اجرا کن.",
                        "No readable files were found in this scan scope. Check storage access and common folders, or run a deep scan for broader coverage."
                    ),
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
            if (report.scannedCount > report.items.size) {
                Text(
                    tr(fa, "۶۰ نتیجه اول نمایش داده شده‌اند؛ مجموعاً ${report.scannedCount} فایل اسکن شده است.", "Showing the first 60 of ${report.scannedCount} scanned files."),
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

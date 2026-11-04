package com.antivirusalai

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.antivirusalai.engine.EvidenceSeverity
import com.antivirusalai.engine.ScanEngine
import com.antivirusalai.engine.ScanResult
import com.antivirusalai.engine.ScanTooLargeException
import com.antivirusalai.engine.ScanVerdict
import com.antivirusalai.remediation.QuarantineManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

private val Background = Color(0xFF07111F)
private val Panel = Color(0xFF111F31)
private val PanelElevated = Color(0xFF172A40)
private val Accent = Color(0xFF39D7CF)
private val AccentBlue = Color(0xFF6F9CFF)
private val Muted = Color(0xFF9CB0C5)
private val SoftWhite = Color(0xFFEAF2FA)
private val Warning = Color(0xFFFFC46B)
private val Danger = Color(0xFFFF777F)
private val Success = Color(0xFF73E0B0)

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
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var notice by remember { mutableStateOf<String?>(null) }
    var selectedPlan by remember { mutableStateOf<String?>(null) }
    var featureInfo by remember { mutableStateOf<String?>(null) }
    var showPrivacy by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }
    val fa = language == "fa"

    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            selectedUri = uri
            try {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } catch (_: SecurityException) {
                // Some document providers grant only a temporary read permission.
            }
            scanning = true
            scanResult = null
            errorMessage = null
            notice = null
            activeTab = MainTab.SCAN.key
            scope.launch {
                try {
                    scanResult = ScanEngine.scan(context.applicationContext, uri)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    errorMessage = if (error is ScanTooLargeException) {
                        if (fa) "حجم فایل از سقف ۲۰۰ مگابایت بیشتر است." else error.message
                    } else {
                        error.message ?: tr(fa, "اسکن انجام نشد.", "Scan failed.")
                    }
                } finally {
                    scanning = false
                }
            }
        }
    }

    val launchFileScan: () -> Unit = {
        if (!scanning) picker.launch(arrayOf("*/*"))
    }
    val launchApkScan: () -> Unit = {
        if (!scanning) picker.launch(arrayOf("application/vnd.android.package-archive"))
    }

    CompositionLocalProvider(
        LocalLayoutDirection provides if (fa) LayoutDirection.Rtl else LayoutDirection.Ltr
    ) {
        MaterialTheme(
            colorScheme = darkColorScheme(
                primary = Accent,
                onPrimary = Background,
                background = Background,
                surface = Panel,
                onSurface = SoftWhite,
                secondary = AccentBlue,
                error = Danger
            )
        ) {
            Scaffold(
                containerColor = Background,
                bottomBar = {
                    AppBottomBar(
                        activeTab = activeTab,
                        fa = fa,
                        onSelect = { activeTab = it.key }
                    )
                }
            ) { innerPadding ->
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(
                            Brush.verticalGradient(
                                colors = listOf(Color(0xFF0B1C30), Background, Background)
                            )
                        )
                        .padding(innerPadding)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(horizontal = 18.dp, vertical = 18.dp),
                        verticalArrangement = Arrangement.spacedBy(18.dp)
                    ) {
                        AppHeader(
                            fa = fa,
                            onLanguageChange = { language = if (fa) "en" else "fa" },
                            onSettings = { activeTab = MainTab.SETTINGS.key }
                        )

                        when (activeTab) {
                            MainTab.HOME.key -> HomeScreen(
                                fa = fa,
                                scanning = scanning,
                                lastResult = scanResult,
                                onQuickScan = launchFileScan,
                                onApkScan = launchApkScan,
                                onOpenScan = { activeTab = MainTab.SCAN.key },
                                onOpenTools = { activeTab = MainTab.TOOLS.key },
                                onOpenStore = { activeTab = MainTab.STORE.key }
                            )

                            MainTab.SCAN.key -> ScanScreen(
                                fa = fa,
                                scanning = scanning,
                                result = scanResult,
                                errorMessage = errorMessage,
                                notice = notice,
                                quarantining = quarantining,
                                onFileScan = launchFileScan,
                                onApkScan = launchApkScan,
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
                                                    "نسخه رمزنگاری‌شده در فضای خصوصی ذخیره شد. شناسه: ${receipt.id.take(8)}. فایل اصلی در محل قبلی باقی مانده است.",
                                                    "An encrypted copy was saved in private storage. ID: ${receipt.id.take(8)}. The original file remains unchanged."
                                                )
                                            } catch (cancelled: CancellationException) {
                                                throw cancelled
                                            } catch (error: Exception) {
                                                notice = error.message ?: tr(fa, "ذخیره قرنطینه انجام نشد.", "Quarantine copy failed.")
                                            } finally {
                                                quarantining = false
                                            }
                                        }
                                    }
                                },
                                onClearReport = {
                                    scanResult = null
                                    errorMessage = null
                                    notice = null
                                }
                            )

                            MainTab.TOOLS.key -> ToolsScreen(
                                fa = fa,
                                lastResult = scanResult,
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
                                "نسخه اولیه ۰٫۱٫۰ • نتایج این نسخه فقط بر پایه قابلیت‌های پیاده‌سازی‌شده گزارش می‌شوند.",
                                "Early build 0.1.0 • Reports are limited to capabilities implemented in this version."
                            ),
                            color = Muted,
                            style = MaterialTheme.typography.bodySmall,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth().padding(top = 4.dp, bottom = 8.dp)
                        )
                    }
                }
            }
        }
    }

    selectedPlan?.let { plan ->
        AlertDialog(
            onDismissRequest = { selectedPlan = null },
            containerColor = PanelElevated,
            title = { Text(tr(fa, "فروشگاه ANTIVIRUS AL AI", "ANTIVIRUS AL AI Store"), color = SoftWhite) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        tr(fa, "طرح انتخاب‌شده: $plan", "Selected plan: $plan"),
                        color = Accent,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        tr(
                            fa,
                            "درگاه پرداخت Google Play و مدیریت اشتراک هنوز به پروژه متصل نشده است. هیچ خرید، برداشت وجه یا فعال‌سازی اشتراکی انجام نمی‌شود. این بخش فعلاً کاتالوگ و پیش‌نمایش طرح‌هاست.",
                            "Google Play Billing and subscription management are not connected yet. No purchase, charge, or subscription activation will occur. This is currently a plan catalogue preview."
                        ),
                        color = Muted
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = { selectedPlan = null },
                    colors = ButtonDefaults.buttonColors(containerColor = Accent)
                ) { Text(tr(fa, "متوجه شدم", "Got it")) }
            }
        )
    }

    featureInfo?.let { feature ->
        AlertDialog(
            onDismissRequest = { featureInfo = null },
            containerColor = PanelElevated,
            title = { Text(featureTitle(fa, feature), color = SoftWhite) },
            text = { Text(featureDescription(fa, feature), color = Muted) },
            confirmButton = {
                Button(
                    onClick = { featureInfo = null },
                    colors = ButtonDefaults.buttonColors(containerColor = Accent)
                ) { Text(tr(fa, "بستن", "Close")) }
            }
        )
    }

    if (showPrivacy) {
        AlertDialog(
            onDismissRequest = { showPrivacy = false },
            containerColor = PanelElevated,
            title = { Text(tr(fa, "حریم خصوصی", "Privacy"), color = SoftWhite) },
            text = {
                Text(
                    tr(
                        fa,
                        "در نسخه فعلی فقط فایلی که خودت از انتخاب‌گر Android مشخص می‌کنی خوانده می‌شود. محتوای فایل به سرور ارسال نمی‌شود. برای قرنطینه، یک نسخه رمزنگاری‌شده در فضای خصوصی برنامه ذخیره می‌شود و فایل اصلی دست‌نخورده می‌ماند. دسترسی به اطلاعات خصوصی برنامه‌های دیگر یا اسکن کامل دستگاه در این نسخه وجود ندارد.",
                        "In this version, only a file you explicitly select through Android's document picker is read. File contents are not uploaded. Quarantine stores an encrypted copy in private app storage and leaves the original unchanged. This version does not access other apps' private data or perform a full-device scan."
                    ),
                    color = Muted
                )
            },
            confirmButton = {
                Button(onClick = { showPrivacy = false }) { Text(tr(fa, "بستن", "Close")) }
            }
        )
    }

    if (showAbout) {
        AlertDialog(
            onDismissRequest = { showAbout = false },
            containerColor = PanelElevated,
            title = { Text("ANTIVIRUS AL AI", color = SoftWhite) },
            text = {
                Text(
                    tr(
                        fa,
                        "نسخه ۰٫۱٫۰ • Android • موتور اسکن محلی و گزارش شفاف. قابلیت‌های آنلاین، پایش بلادرنگ، پرداخت و برخی ابزارهای امنیتی هنوز در دست توسعه‌اند.",
                        "Version 0.1.0 • Android • Local scan engine with explainable reporting. Online intelligence, real-time monitoring, billing, and several security tools are still under development."
                    ),
                    color = Muted
                )
            },
            confirmButton = {
                Button(onClick = { showAbout = false }) { Text(tr(fa, "بستن", "Close")) }
            }
        )
    }
}

@Composable
private fun AppHeader(
    fa: Boolean,
    onLanguageChange: () -> Unit,
    onSettings: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Box(
                modifier = Modifier
                    .size(46.dp)
                    .background(
                        Brush.linearGradient(listOf(Accent, AccentBlue)),
                        RoundedCornerShape(15.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text("◈", color = Background, fontSize = 27.sp, fontWeight = FontWeight.Bold)
            }
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    "ANTIVIRUS AL AI",
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.ExtraBold
                )
                Text(
                    tr(fa, "امنیت شفاف و هوشمند", "SMART • TRANSPARENT SECURITY"),
                    color = Muted,
                    fontSize = 9.sp,
                    letterSpacing = 1.sp
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
            SmallIconButton(label = if (fa) "EN" else "فا", onClick = onLanguageChange)
            SmallIconButton(label = "⚙", onClick = onSettings)
        }
    }
}

@Composable
private fun AppBottomBar(
    activeTab: String,
    fa: Boolean,
    onSelect: (MainTab) -> Unit
) {
    NavigationBar(
        containerColor = Color(0xFF0C1929),
        contentColor = SoftWhite,
        tonalElevation = 0.dp
    ) {
        val tabs = listOf(
            Triple(MainTab.HOME, "⌂", tr(fa, "خانه", "Home")),
            Triple(MainTab.SCAN, "◎", tr(fa, "اسکن", "Scan")),
            Triple(MainTab.TOOLS, "✣", tr(fa, "ابزارها", "Tools")),
            Triple(MainTab.STORE, "◇", tr(fa, "فروشگاه", "Store")),
            Triple(MainTab.SETTINGS, "⚙", tr(fa, "تنظیمات", "Settings"))
        )
        tabs.forEach { (tab, icon, label) ->
            NavigationBarItem(
                selected = activeTab == tab.key,
                onClick = { onSelect(tab) },
                icon = { Text(icon, fontSize = 19.sp, fontWeight = FontWeight.SemiBold) },
                label = { Text(label, fontSize = 10.sp, maxLines = 1) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = Accent,
                    selectedTextColor = Accent,
                    indicatorColor = Accent.copy(alpha = 0.13f),
                    unselectedIconColor = Muted,
                    unselectedTextColor = Muted
                )
            )
        }
    }
}

@Composable
private fun HomeScreen(
    fa: Boolean,
    scanning: Boolean,
    lastResult: ScanResult?,
    onQuickScan: () -> Unit,
    onApkScan: () -> Unit,
    onOpenScan: () -> Unit,
    onOpenTools: () -> Unit,
    onOpenStore: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                tr(fa, "مرکز امنیت", "Security overview"),
                color = Color.White,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            Text(
                tr(fa, "وضعیت قابلیت‌های فعال برنامه را از همین‌جا ببین.", "See the actual status of the protection features available in this build."),
                color = Muted,
                style = MaterialTheme.typography.bodyMedium
            )
        }

        Card(
            shape = RoundedCornerShape(26.dp),
            colors = CardDefaults.cardColors(containerColor = PanelElevated)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        Brush.linearGradient(
                            listOf(Color(0xFF173B4A), Color(0xFF172C48), Color(0xFF18263D))
                        )
                    )
                    .padding(20.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(13.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        StatusPill(
                            text = tr(fa, "موتور محلی آماده", "LOCAL ENGINE READY"),
                            color = Accent
                        )
                        Text("✦", color = Accent, fontSize = 24.sp)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                            Text(
                                tr(fa, "اسکن با کنترل خودت", "Security on your terms"),
                                color = Color.White,
                                fontSize = 22.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                tr(
                                    fa,
                                    "فایل را انتخاب کن تا موتور محلی آن را بررسی کند. محتوای فایل از دستگاه خارج نمی‌شود.",
                                    "Choose a file for local inspection. File contents stay on your device."
                                ),
                                color = Color(0xFFC3D5E5),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                        Spacer(Modifier.width(10.dp))
                        Box(
                            modifier = Modifier
                                .size(76.dp)
                                .border(1.dp, Accent.copy(alpha = 0.55f), CircleShape)
                                .background(Accent.copy(alpha = 0.08f), CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("⬡", color = Accent, fontSize = 49.sp)
                        }
                    }
                    Button(
                        onClick = onOpenScan,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = Accent),
                        shape = RoundedCornerShape(15.dp)
                    ) {
                        Text(
                            if (scanning) tr(fa, "در حال اسکن…", "Scanning…")
                            else tr(fa, "ورود به مرکز اسکن", "Open scan center"),
                            color = Background,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            MetricCard(
                modifier = Modifier.weight(1f),
                title = tr(fa, "اسکن اخیر", "Last scan"),
                value = lastResult?.let { tr(fa, "انجام شد", "Done") } ?: tr(fa, "هنوز", "None"),
                detail = lastResult?.displayName ?: tr(fa, "گزارشی ثبت نشده", "No report yet"),
                accent = AccentBlue
            )
            MetricCard(
                modifier = Modifier.weight(1f),
                title = tr(fa, "بانک تهدید", "Threat feed"),
                value = tr(fa, "متصل نیست", "Not linked"),
                detail = tr(fa, "کلید انتشار تنظیم نشده", "Publisher key not configured"),
                accent = Warning
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            MetricCard(
                modifier = Modifier.weight(1f),
                title = tr(fa, "محافظت بلادرنگ", "Real-time guard"),
                value = tr(fa, "غیرفعال", "Inactive"),
                detail = tr(fa, "در حال توسعه", "In development"),
                accent = Danger
            )
            MetricCard(
                modifier = Modifier.weight(1f),
                title = tr(fa, "حریم خصوصی", "Privacy"),
                value = tr(fa, "محلی", "On-device"),
                detail = tr(fa, "بدون آپلود فایل", "No file uploads"),
                accent = Success
            )
        }

        SectionHeading(
            title = tr(fa, "شروع سریع", "Quick actions"),
            subtitle = tr(fa, "عملیات واقعی در نسخه فعلی", "Available in this version")
        )
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            ActionTile(
                modifier = Modifier.weight(1f),
                icon = "⌕",
                title = tr(fa, "اسکن فایل", "File scan"),
                caption = tr(fa, "انتخاب یک فایل", "Choose one file"),
                onClick = onQuickScan
            )
            ActionTile(
                modifier = Modifier.weight(1f),
                icon = "▣",
                title = tr(fa, "تحلیل APK", "APK analysis"),
                caption = tr(fa, "مجوز و امضا", "Permissions & signer"),
                onClick = onApkScan
            )
        }

        SectionHeading(
            title = tr(fa, "ابزارهای امنیتی", "Security toolkit"),
            subtitle = tr(fa, "قابلیت‌های قابل استفاده و در دست توسعه", "Available and planned modules")
        )
        ActionTile(
            modifier = Modifier.fillMaxWidth(),
            icon = "✣",
            title = tr(fa, "مرکز ابزارها", "Open security tools"),
            caption = tr(fa, "قرنطینه، آسیب‌پذیری، لینک‌ها و شبکه", "Quarantine, vulnerabilities, links and network"),
            onClick = onOpenTools
        )
        ActionTile(
            modifier = Modifier.fillMaxWidth(),
            icon = "◇",
            title = tr(fa, "طرح‌های اشتراک و فروشگاه", "Plans and store"),
            caption = tr(fa, "مشاهده امکانات FREE، PLUS و FAMILY", "Explore FREE, PLUS and FAMILY plans"),
            onClick = onOpenStore
        )

        InfoBanner(
            title = tr(fa, "شفافیت وضعیت", "Protection status"),
            body = tr(
                fa,
                "این نسخه اسکن کامل دستگاه، حذف خودکار برنامه‌های دیگر یا محافظت بلادرنگ ارائه نمی‌کند. نتیجه «بدون نشانگر شناخته‌شده» تضمین ایمنی نیست.",
                "This version does not offer a full-device scan, automatic removal of other apps, or real-time protection. “No known indicator” is not a safety guarantee."
            ),
            warning = true
        )
    }
}

@Composable
private fun ScanScreen(
    fa: Boolean,
    scanning: Boolean,
    result: ScanResult?,
    errorMessage: String?,
    notice: String?,
    quarantining: Boolean,
    onFileScan: () -> Unit,
    onApkScan: () -> Unit,
    onQuarantine: () -> Unit,
    onClearReport: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(15.dp)) {
        SectionHeading(
            title = tr(fa, "مرکز اسکن", "Scan center"),
            subtitle = tr(fa, "یک فایل را آگاهانه انتخاب کن؛ برنامه همان فایل را در فضای محلی بررسی می‌کند.", "Select a file deliberately. The app inspects that file locally.")
        )

        ScanModeCard(
            icon = "⌕",
            title = tr(fa, "اسکن سریع فایل", "Quick file scan"),
            description = tr(fa, "محاسبه SHA-256 و بررسی نشانگرهای محلی برای فایل انتخابی. قالب‌های پشتیبانی‌نشده ناشناخته گزارش می‌شوند.", "SHA-256 hashing and local indicator checks for the selected file. Unsupported formats are reported as unknown."),
            tag = tr(fa, "محلی • بدون آپلود", "LOCAL • NO UPLOAD"),
            enabled = !scanning,
            onClick = onFileScan
        )
        ScanModeCard(
            icon = "▣",
            title = tr(fa, "تحلیل APK", "APK analysis"),
            description = tr(fa, "بررسی فراداده، مجوزها، اجزای export شده و اثرانگشت گواهی امضا؛ بدون نصب یا اجرای APK.", "Inspect metadata, permissions, exported components and signer fingerprint without installing or executing the APK."),
            tag = tr(fa, "تحلیل ایستا", "STATIC ANALYSIS"),
            enabled = !scanning,
            onClick = onApkScan
        )
        ScanModeCard(
            icon = "▦",
            title = tr(fa, "اسکن کامل دستگاه", "Full device scan"),
            description = tr(fa, "در این نسخه در دسترس نیست. محدودیت‌های Android اجازه دسترسی آزاد به داده خصوصی برنامه‌های دیگر را نمی‌دهد.", "Not available in this build. Android does not allow unrestricted access to other apps' private data."),
            tag = tr(fa, "در دست توسعه", "IN DEVELOPMENT"),
            enabled = false,
            onClick = {}
        )

        if (scanning) {
            Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(18.dp)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(tr(fa, "در حال بررسی فایل انتخابی…", "Inspecting selected file…"), color = SoftWhite, fontWeight = FontWeight.SemiBold)
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth(),
                        color = Accent,
                        trackColor = Accent.copy(alpha = 0.15f)
                    )
                    Text(tr(fa, "فایل اجرا یا نصب نمی‌شود.", "The file is not executed or installed."), color = Muted, style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        errorMessage?.let {
            InfoBanner(tr(fa, "اسکن انجام نشد", "Scan failed"), it, warning = true)
        }
        notice?.let {
            InfoBanner(tr(fa, "وضعیت قرنطینه", "Quarantine status"), it, warning = false)
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

        if (result == null && errorMessage == null) {
            InfoBanner(
                title = tr(fa, "قبل از اسکن", "Before scanning"),
                body = tr(
                    fa,
                    "فقط فایل‌های متعلق به خودت یا فایل‌هایی را که اجازه بررسی‌شان را داری انتخاب کن. این موتور هنوز بانک امضای بدافزار تولیدی ندارد.",
                    "Select only files you own or are authorized to inspect. This engine does not yet contain a production malware-signature database."
                ),
                warning = false
            )
        }
    }
}

@Composable
private fun ToolsScreen(
    fa: Boolean,
    lastResult: ScanResult?,
    onFeature: (String) -> Unit,
    onOpenScan: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        SectionHeading(
            title = tr(fa, "جعبه‌ابزار امنیتی", "Security toolkit"),
            subtitle = tr(fa, "ماژول‌ها بر اساس وضعیت واقعی توسعه تفکیک شده‌اند.", "Modules are labelled according to their actual implementation status.")
        )

        ToolCard(
            icon = "⬡",
            title = tr(fa, "فضای قرنطینه رمزنگاری‌شده", "Encrypted quarantine"),
            description = tr(fa, "در نسخه فعلی فقط نسخه رمزنگاری‌شده فایل انتخابی در حافظه خصوصی ذخیره می‌شود؛ فایل اصلی حذف نمی‌شود.", "This build stores only an encrypted copy of a selected file in private storage; the original is not deleted."),
            status = tr(fa, "نسخه اولیه فعال", "MVP available"),
            statusColor = Accent,
            onClick = { onFeature("quarantine") }
        )
        ToolCard(
            icon = "⌁",
            title = tr(fa, "تحلیل آسیب‌پذیری APK", "APK vulnerability intelligence"),
            description = tr(fa, "برنامه‌ریزی‌شده برای شناسایی SDK قدیمی، کتابخانه‌های شناخته‌شده و پیکربندی‌های ناامن.", "Planned checks for outdated SDKs, known libraries and insecure configurations."),
            status = tr(fa, "در حال توسعه", "In development"),
            statusColor = Warning,
            onClick = { onFeature("vulnerability") }
        )
        ToolCard(
            icon = "◎",
            title = tr(fa, "محافظ لینک و فیشینگ", "Scam & phishing shield"),
            description = tr(fa, "تحلیل URL و پیوندهایی که کاربر آگاهانه برای بررسی انتخاب می‌کند.", "Analysis of URLs and links that the user deliberately submits for review."),
            status = tr(fa, "در برنامه توسعه", "Planned"),
            statusColor = Muted,
            onClick = { onFeature("phishing") }
        )
        ToolCard(
            icon = "⌘",
            title = tr(fa, "محافظ شبکه", "Network guard"),
            description = tr(fa, "بررسی گزینه‌های محافظت DNS و VPN محلی با رعایت محدودیت‌های Android و سیاست فروشگاه.", "DNS and local VPN protection options, subject to Android and store policies."),
            status = tr(fa, "در برنامه توسعه", "Planned"),
            statusColor = Muted,
            onClick = { onFeature("network") }
        )
        ToolCard(
            icon = "◈",
            title = tr(fa, "مغز امنیتی AL AI", "AL AI security brain"),
            description = tr(fa, "تجمیع شواهد موتورهای مختلف، امتیاز ریسک و توضیح دلیل نتیجه؛ فعلاً تحلیل‌گر چندموتوره فعال نیست.", "Combines evidence from multiple engines into explainable risk assessments; multi-engine reasoning is not active yet."),
            status = tr(fa, "هسته اولیه", "Foundation only"),
            statusColor = AccentBlue,
            onClick = { onFeature("brain") }
        )
        ToolCard(
            icon = "⛨",
            title = tr(fa, "دفاع از خود برنامه", "Self-defense engine"),
            description = tr(fa, "کنترل‌های پایه پیکربندی و انتشار امن؛ پایش بلادرنگ دست‌کاری برنامه هنوز پیاده‌سازی نشده است.", "Baseline configuration and release-security controls; runtime tamper monitoring is not implemented yet."),
            status = tr(fa, "پایه‌ای", "Baseline"),
            statusColor = AccentBlue,
            onClick = { onFeature("selfdefense") }
        )

        if (lastResult != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Panel),
                shape = RoundedCornerShape(20.dp)
            ) {
                Column(Modifier.padding(17.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(tr(fa, "آخرین گزارش", "Latest report"), color = SoftWhite, fontWeight = FontWeight.Bold)
                    Text(lastResult.displayName, color = Muted, style = MaterialTheme.typography.bodySmall)
                    Text(verdictTitle(lastResult.verdict, fa), color = verdictColor(lastResult.verdict), fontWeight = FontWeight.SemiBold)
                    OutlinedButton(onClick = onOpenScan) {
                        Text(tr(fa, "مشاهده جزئیات گزارش", "View report details"))
                    }
                }
            }
        }
    }
}

@Composable
private fun StoreScreen(
    fa: Boolean,
    onSelectPlan: (String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Card(
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = PanelElevated)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Brush.linearGradient(listOf(Color(0xFF204B56), Color(0xFF1B3150), Color(0xFF202845))))
                    .padding(20.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
                    StatusPill(tr(fa, "فروشگاه رسمی داخل برنامه", "IN-APP PLAN CATALOGUE"), Accent)
                    Text(
                        tr(fa, "امنیت پایه همیشه در دسترس", "Essential security stays accessible"),
                        color = Color.White,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Text(
                        tr(
                            fa,
                            "طرح‌ها قابلیت‌های تکمیلی آینده را معرفی می‌کنند. امکانات ضروری اسکن و گزارش پایه قرار نیست پشت اشتراک قفل شوند.",
                            "Plans describe future premium capabilities. Essential scanning and basic reports are not intended to be paywalled."
                        ),
                        color = Color(0xFFC7D9E7),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }

        InfoBanner(
            title = tr(fa, "پرداخت هنوز فعال نیست", "Checkout is not active"),
            body = tr(
                fa,
                "این صفحه کاتالوگ طرح‌هاست. پرداخت Google Play، قیمت‌گذاری منطقه‌ای، بازیابی خرید و مدیریت اشتراک هنوز پیاده‌سازی نشده‌اند؛ هیچ مبلغی دریافت نمی‌شود.",
                "This is a plan catalogue. Google Play Billing, regional pricing, purchase restoration and subscription management are not implemented. No money will be charged."
            ),
            warning = true
        )

        PlanCard(
            fa = fa,
            name = "FREE",
            subtitle = tr(fa, "شروع امن و کاربردی", "A useful starting point"),
            price = tr(fa, "رایگان", "Free"),
            badge = tr(fa, "طرح فعلی", "CURRENT PLAN"),
            highlighted = true,
            features = listOf(
                tr(fa, "اسکن فایل انتخابی و تحلیل پایه APK", "Selected-file scan and basic APK analysis"),
                tr(fa, "گزارش شفاف و نمایش شواهد", "Explainable reports and evidence"),
                tr(fa, "ذخیره نسخه رمزنگاری‌شده فایل", "Encrypted private copy"),
                tr(fa, "عملکرد محلی بدون ارسال فایل", "Local processing without file uploads")
            ),
            onSelect = { onSelectPlan("FREE") }
        )
        PlanCard(
            fa = fa,
            name = "PLUS MONTHLY",
            subtitle = tr(fa, "اشتراک ماهانه", "Monthly subscription"),
            price = tr(fa, "قیمت هنگام عرضه", "Price at launch"),
            badge = tr(fa, "در برنامه توسعه", "PLANNED"),
            highlighted = false,
            features = listOf(
                tr(fa, "اعتبارسنجی بانک تهدید امضاشده پس از راه‌اندازی", "Verified signed threat-feed updates once launched"),
                tr(fa, "بررسی اعتبار هش به‌صورت اختیاری", "Optional hash-reputation checks"),
                tr(fa, "گزارش‌های تکمیلی امنیتی", "Expanded security reports")
            ),
            onSelect = { onSelectPlan("PLUS MONTHLY") }
        )
        PlanCard(
            fa = fa,
            name = "PLUS ANNUAL",
            subtitle = tr(fa, "اشتراک سالانه", "Annual subscription"),
            price = tr(fa, "قیمت هنگام عرضه", "Price at launch"),
            badge = tr(fa, "در برنامه توسعه", "PLANNED"),
            highlighted = false,
            features = listOf(
                tr(fa, "تمام قابلیت‌های طرح PLUS", "All PLUS features"),
                tr(fa, "مدیریت تمدید و بازیابی خرید", "Subscription renewal and purchase restoration"),
                tr(fa, "قیمت‌گذاری منطقه‌ای شفاف", "Transparent regional pricing")
            ),
            onSelect = { onSelectPlan("PLUS ANNUAL") }
        )
        PlanCard(
            fa = fa,
            name = "PRO FAMILY",
            subtitle = tr(fa, "برای چند دستگاه", "For multiple devices"),
            price = tr(fa, "قیمت هنگام عرضه", "Price at launch"),
            badge = tr(fa, "در برنامه توسعه", "PLANNED"),
            highlighted = false,
            features = listOf(
                tr(fa, "مدیریت چند دستگاه با رضایت صاحبان آن‌ها", "Multi-device management with each owner's consent"),
                tr(fa, "نمای کلی وضعیت امنیتی خانواده", "Family security overview"),
                tr(fa, "مدیریت اعضا و اشتراک", "Member and subscription management")
            ),
            onSelect = { onSelectPlan("PRO FAMILY") }
        )
        PlanCard(
            fa = fa,
            name = "LIFETIME OFFLINE",
            subtitle = tr(fa, "مجوز یک‌باره برای امکانات محلی", "One-time licence for local features"),
            price = tr(fa, "قیمت هنگام عرضه", "Price at launch"),
            badge = tr(fa, "در برنامه توسعه", "PLANNED"),
            highlighted = false,
            features = listOf(
                tr(fa, "قابلیت‌های محلی بدون وابستگی به سرویس ابری", "Local capabilities without cloud dependency"),
                tr(fa, "بدون تمدید اشتراک", "No subscription renewal"),
                tr(fa, "به‌روزرسانی‌های امنیتی طبق شرایط انتشار", "Security updates subject to release terms")
            ),
            onSelect = { onSelectPlan("LIFETIME OFFLINE") }
        )
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
    Column(verticalArrangement = Arrangement.spacedBy(13.dp)) {
        SectionHeading(
            title = tr(fa, "تنظیمات", "Settings"),
            subtitle = tr(fa, "زبان، حریم خصوصی و اطلاعات برنامه", "Language, privacy and app information")
        )
        SettingsRow(
            icon = "文",
            title = tr(fa, "زبان برنامه", "App language"),
            description = tr(fa, "فارسی / English", "Persian / English"),
            action = if (fa) "EN" else "فا",
            onClick = onLanguageChange
        )
        SettingsRow(
            icon = "⌑",
            title = tr(fa, "حریم خصوصی و داده‌ها", "Privacy and data"),
            description = tr(fa, "چه داده‌ای خوانده می‌شود و چه چیزی ارسال نمی‌شود", "What is read and what is not uploaded"),
            action = "›",
            onClick = onPrivacy
        )
        SettingsRow(
            icon = "◈",
            title = tr(fa, "اطلاعات برنامه", "About"),
            description = tr(fa, "نسخه ۰٫۱٫۰ و وضعیت قابلیت‌ها", "Version 0.1.0 and feature status"),
            action = "›",
            onClick = onAbout
        )
        SettingsRow(
            icon = "♧",
            title = tr(fa, "امنیت و مجوزها", "Security and permissions"),
            description = tr(fa, "توضیح مرزهای امنیتی نسخه فعلی", "Security boundaries in the current build"),
            action = "›",
            onClick = { onFeature("permissions") }
        )
        SettingsRow(
            icon = "✉",
            title = tr(fa, "پشتیبانی و گزارش مشکل", "Support and issue reporting"),
            description = tr(fa, "مسیر ارتباطی پس از آماده شدن کانال رسمی", "Official support channel will be published before launch"),
            action = "›",
            onClick = { onFeature("support") }
        )
        InfoBanner(
            title = tr(fa, "نسخه آزمایشی", "Development build"),
            body = tr(fa, "این نسخه برای تکمیل و آزمون ساخته شده است؛ هنوز آماده عرضه عمومی یا ادعای محافظت کامل نیست.", "This build is still being developed and tested. It is not ready for public release or claims of complete protection."),
            warning = true
        )
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
        colors = CardDefaults.cardColors(containerColor = Panel)
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(tr(fa, "گزارش اسکن", "Scan report"), color = SoftWhite, fontWeight = FontWeight.Bold)
                StatusPill(verdictBadge(result.verdict, fa), verdictColor(result.verdict))
            }
            Text(result.displayName, color = Color.White, fontWeight = FontWeight.SemiBold)
            Text(verdictTitle(result.verdict, fa), color = verdictColor(result.verdict), fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Text(verdictDescription(result.verdict, fa), color = Muted, style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricCard(
                    modifier = Modifier.weight(1f),
                    title = tr(fa, "حجم", "Size"),
                    value = formatBytes(result.sizeBytes),
                    detail = tr(fa, "اندازه فایل", "File size"),
                    accent = AccentBlue
                )
                MetricCard(
                    modifier = Modifier.weight(1f),
                    title = tr(fa, "زمان", "Duration"),
                    value = "${result.durationMillis} ms",
                    detail = tr(fa, "زمان تحلیل", "Analysis time"),
                    accent = Accent
                )
            }
            Text("SHA-256", color = SoftWhite, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
            Text(result.sha256, color = Muted, fontSize = 10.sp, lineHeight = 15.sp)
            result.apkMetadata?.let { apk ->
                Surface(
                    color = PanelElevated,
                    shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                        Text(tr(fa, "فراداده APK", "APK metadata"), color = SoftWhite, fontWeight = FontWeight.SemiBold)
                        DetailLine(tr(fa, "شناسه بسته", "Package"), apk.packageName)
                        DetailLine("Target SDK", apk.targetSdk.toString())
                        DetailLine(tr(fa, "مجوزهای درخواستی", "Requested permissions"), apk.requestedPermissions.size.toString())
                        DetailLine(tr(fa, "اجزای قابل دسترس", "Exported components"), apk.exportedComponentCount.toString())
                        apk.signingCertificateSha256?.let { DetailLine("Signer SHA-256", it) }
                    }
                }
            }
            Text(tr(fa, "شواهد و نشانه‌ها", "Evidence and indicators"), color = SoftWhite, fontWeight = FontWeight.Bold)
            result.evidence.forEach { item ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(9.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Box(
                        modifier = Modifier
                            .padding(top = 4.dp)
                            .size(8.dp)
                            .background(
                                when (item.severity) {
                                    EvidenceSeverity.HIGH -> Warning
                                    EvidenceSeverity.MEDIUM -> AccentBlue
                                    EvidenceSeverity.LOW -> Accent
                                    EvidenceSeverity.INFO -> Muted
                                },
                                CircleShape
                            )
                    )
                    Column(verticalArrangement = Arrangement.spacedBy(3.dp), modifier = Modifier.weight(1f)) {
                        Text(item.title, color = SoftWhite, fontWeight = FontWeight.Medium, fontSize = 13.sp)
                        Text(item.detail, color = Muted, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            Button(
                onClick = onQuarantine,
                enabled = !quarantining,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Accent),
                shape = RoundedCornerShape(14.dp)
            ) {
                Text(
                    if (quarantining) tr(fa, "در حال ذخیره…", "Saving…")
                    else tr(fa, "ذخیره نسخه رمزنگاری‌شده", "Save encrypted copy"),
                    color = Background,
                    fontWeight = FontWeight.Bold
                )
            }
            Text(
                tr(
                    fa,
                    "این کار فایل اصلی را حذف یا غیرفعال نمی‌کند؛ فقط یک نسخه رمزنگاری‌شده در فضای خصوصی برنامه می‌سازد.",
                    "This does not delete or disable the original. It creates an encrypted copy in private app storage."
                ),
                color = Muted,
                style = MaterialTheme.typography.bodySmall
            )
            OutlinedButton(onClick = onClear, modifier = Modifier.fillMaxWidth()) {
                Text(tr(fa, "پاک کردن گزارش از صفحه", "Clear report from screen"))
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
        colors = CardDefaults.cardColors(containerColor = if (enabled) Panel else Panel.copy(alpha = 0.65f))
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(13.dp),
            verticalAlignment = Alignment.Top
        ) {
            Box(
                modifier = Modifier
                    .size(45.dp)
                    .background(if (enabled) Accent.copy(alpha = 0.12f) else Muted.copy(alpha = 0.10f), RoundedCornerShape(14.dp)),
                contentAlignment = Alignment.Center
            ) {
                Text(icon, color = if (enabled) Accent else Muted, fontSize = 25.sp, fontWeight = FontWeight.Bold)
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(title, color = if (enabled) SoftWhite else Muted, fontWeight = FontWeight.Bold)
                }
                Text(description, color = Muted, style = MaterialTheme.typography.bodySmall)
                StatusPill(tag, if (enabled) Accent else Warning)
            }
            Text(if (enabled) "←" else "–", color = if (enabled) Accent else Muted, fontSize = 20.sp)
        }
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
            .then(if (highlighted) Modifier.border(1.dp, Accent.copy(alpha = 0.7f), RoundedCornerShape(21.dp)) else Modifier),
        colors = CardDefaults.cardColors(containerColor = if (highlighted) Color(0xFF132D3A) else Panel),
        shape = RoundedCornerShape(21.dp)
    ) {
        Column(Modifier.padding(17.dp), verticalArrangement = Arrangement.spacedBy(11.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(name, color = Color.White, fontSize = 17.sp, fontWeight = FontWeight.ExtraBold)
                    Text(subtitle, color = Muted, style = MaterialTheme.typography.bodySmall)
                }
                StatusPill(badge, if (highlighted) Accent else Muted)
            }
            Text(price, color = Accent, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            features.forEach { feature ->
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Top) {
                    Text("✓", color = Accent, fontWeight = FontWeight.Bold)
                    Text(feature, color = SoftWhite, style = MaterialTheme.typography.bodySmall)
                }
            }
            OutlinedButton(
                onClick = onSelect,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Accent)
            ) {
                Text(if (highlighted) tr(fa, "طرح فعال", "Current plan") else tr(fa, "مشاهده جزئیات طرح", "View plan details"))
            }
        }
    }
}

@Composable
private fun ToolCard(
    icon: String,
    title: String,
    description: String,
    status: String,
    statusColor: Color,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(19.dp),
        colors = CardDefaults.cardColors(containerColor = Panel)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.Top
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(statusColor.copy(alpha = 0.12f), RoundedCornerShape(13.dp)),
                contentAlignment = Alignment.Center
            ) {
                Text(icon, color = statusColor, fontSize = 23.sp)
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(title, color = SoftWhite, fontWeight = FontWeight.Bold)
                Text(description, color = Muted, style = MaterialTheme.typography.bodySmall)
                StatusPill(status, statusColor)
            }
            Text("›", color = Muted, fontSize = 22.sp)
        }
    }
}

@Composable
private fun SettingsRow(
    icon: String,
    title: String,
    description: String,
    action: String,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(17.dp),
        colors = CardDefaults.cardColors(containerColor = Panel)
    ) {
        Row(
            modifier = Modifier.padding(15.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(41.dp)
                    .background(Accent.copy(alpha = 0.11f), RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center
            ) {
                Text(icon, color = Accent, fontSize = 22.sp)
            }
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(title, color = SoftWhite, fontWeight = FontWeight.SemiBold)
                Text(description, color = Muted, style = MaterialTheme.typography.bodySmall)
            }
            Text(action, color = Accent, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        }
    }
}

@Composable
private fun MetricCard(
    modifier: Modifier,
    title: String,
    value: String,
    detail: String,
    accent: Color
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(17.dp),
        colors = CardDefaults.cardColors(containerColor = Panel)
    ) {
        Column(Modifier.padding(13.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Box(Modifier.size(6.dp).background(accent, CircleShape))
                Text(title, color = Muted, fontSize = 10.sp, fontWeight = FontWeight.Medium)
            }
            Text(value, color = SoftWhite, fontSize = 14.sp, fontWeight = FontWeight.Bold, maxLines = 1)
            Text(detail, color = Muted, fontSize = 9.sp, maxLines = 2, lineHeight = 12.sp)
        }
    }
}

@Composable
private fun ActionTile(
    modifier: Modifier,
    icon: String,
    title: String,
    caption: String,
    onClick: () -> Unit
) {
    Card(
        modifier = modifier.clickable(onClick = onClick),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Panel)
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(39.dp)
                    .background(Accent.copy(alpha = 0.10f), RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center
            ) {
                Text(icon, color = Accent, fontSize = 22.sp)
            }
            Column(verticalArrangement = Arrangement.spacedBy(3.dp), modifier = Modifier.weight(1f)) {
                Text(title, color = SoftWhite, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                Text(caption, color = Muted, fontSize = 9.sp, lineHeight = 12.sp)
            }
        }
    }
}

@Composable
private fun SectionHeading(title: String, subtitle: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, color = Color.White, fontSize = 21.sp, fontWeight = FontWeight.Bold)
        Text(subtitle, color = Muted, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun StatusPill(text: String, color: Color) {
    Surface(
        color = color.copy(alpha = 0.12f),
        shape = RoundedCornerShape(50)
    ) {
        Text(
            text,
            color = color,
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = 0.25.sp,
            modifier = Modifier.padding(horizontal = 9.dp, vertical = 5.dp)
        )
    }
}

@Composable
private fun SmallIconButton(label: String, onClick: () -> Unit) {
    Surface(
        modifier = Modifier.size(40.dp).clickable(onClick = onClick),
        color = Panel,
        shape = RoundedCornerShape(13.dp)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(label, color = Accent, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        }
    }
}

@Composable
private fun InfoBanner(title: String, body: String, warning: Boolean) {
    val color = if (warning) Warning else AccentBlue
    Card(
        shape = RoundedCornerShape(17.dp),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.08f))
    ) {
        Row(
            modifier = Modifier.padding(15.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.Top
        ) {
            Text(if (warning) "!" else "i", color = color, fontSize = 19.sp, fontWeight = FontWeight.Bold)
            Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text(title, color = SoftWhite, fontWeight = FontWeight.SemiBold)
                Text(body, color = Muted, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun DetailLine(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, color = Muted, fontSize = 10.sp)
        Text(value, color = SoftWhite, fontSize = 11.sp)
    }
}

private fun verdictBadge(verdict: ScanVerdict, fa: Boolean): String = when (verdict) {
    ScanVerdict.TEST_MARKER_MATCH -> tr(fa, "آزمایشی", "TEST")
    ScanVerdict.SUSPICIOUS -> tr(fa, "مشکوک", "REVIEW")
    ScanVerdict.NO_KNOWN_INDICATOR -> tr(fa, "بدون تطبیق", "NO MATCH")
    ScanVerdict.UNKNOWN_APK -> tr(fa, "نامشخص", "UNKNOWN")
    ScanVerdict.UNSUPPORTED_FILE -> tr(fa, "پشتیبانی‌نشده", "UNSUPPORTED")
}

private fun verdictTitle(verdict: ScanVerdict, fa: Boolean): String = when (verdict) {
    ScanVerdict.TEST_MARKER_MATCH -> tr(fa, "نشانگر آزمایشی بی‌خطر شناسایی شد", "Benign test marker matched")
    ScanVerdict.SUSPICIOUS -> tr(fa, "نیازمند بررسی بیشتر", "Needs further review")
    ScanVerdict.NO_KNOWN_INDICATOR -> tr(fa, "نشانگر شناخته‌شده‌ای پیدا نشد", "No known indicator found")
    ScanVerdict.UNKNOWN_APK -> tr(fa, "نتیجه نامشخص", "Unknown result")
    ScanVerdict.UNSUPPORTED_FILE -> tr(fa, "این نوع فایل هنوز پشتیبانی نمی‌شود", "File type not covered yet")
}

private fun verdictDescription(verdict: ScanVerdict, fa: Boolean): String = when (verdict) {
    ScanVerdict.TEST_MARKER_MATCH -> tr(fa, "این فقط فایل آزمایشی بی‌خطر پروژه است؛ بدافزار نیست.", "This is the harmless project test fixture, not malware.")
    ScanVerdict.SUSPICIOUS -> tr(fa, "چند نشانه ایستا دیده شده است. این نتیجه اثبات بدافزار بودن نیست.", "Static indicators were found. This is not proof of malware.")
    ScanVerdict.NO_KNOWN_INDICATOR -> tr(fa, "هیچ نشانگر موجود در نسخه فعلی با فایل تطبیق نکرد. این نتیجه تضمین پاک بودن نیست.", "No indicator in this MVP matched. This does not guarantee the file is clean.")
    ScanVerdict.UNKNOWN_APK -> tr(fa, "اطلاعات APK قابل خواندن نبود؛ از اعلام پاک بودن خودداری می‌کنیم.", "APK metadata could not be read; the file is not being declared clean.")
    ScanVerdict.UNSUPPORTED_FILE -> tr(fa, "موتور فعلی تحلیل محتوایی این قالب فایل را انجام نمی‌دهد؛ نتیجه ناشناخته است.", "The current engine does not perform content-aware analysis for this file format; treat it as unknown.")
}

private fun verdictColor(verdict: ScanVerdict): Color = when (verdict) {
    ScanVerdict.TEST_MARKER_MATCH -> AccentBlue
    ScanVerdict.SUSPICIOUS -> Warning
    ScanVerdict.NO_KNOWN_INDICATOR -> Accent
    ScanVerdict.UNKNOWN_APK -> Warning
    ScanVerdict.UNSUPPORTED_FILE -> Muted
}

private fun featureTitle(fa: Boolean, feature: String): String = when (feature) {
    "quarantine" -> tr(fa, "قرنطینه رمزنگاری‌شده", "Encrypted quarantine")
    "vulnerability" -> tr(fa, "تحلیل آسیب‌پذیری APK", "APK vulnerability intelligence")
    "phishing" -> tr(fa, "محافظ فیشینگ", "Phishing shield")
    "network" -> tr(fa, "محافظ شبکه", "Network guard")
    "brain" -> tr(fa, "مغز امنیتی AL AI", "AL AI security brain")
    "selfdefense" -> tr(fa, "دفاع از خود برنامه", "Self-defense engine")
    "permissions" -> tr(fa, "امنیت و مجوزها", "Security and permissions")
    else -> tr(fa, "پشتیبانی", "Support")
}

private fun featureDescription(fa: Boolean, feature: String): String = when (feature) {
    "quarantine" -> tr(fa, "در حال حاضر با درخواست کاربر یک نسخه AES-GCM رمزنگاری‌شده در فضای خصوصی برنامه ذخیره می‌شود و هش آن بررسی می‌شود. فایل اصلی حذف نمی‌شود. فهرست‌کردن، بازیابی و حذف امن نسخه‌های قرنطینه در مرحله بعد ساخته می‌شود.", "At the user's request, an AES-GCM encrypted copy is stored in private app storage and its hash is verified. The original is not removed. Listing, restoring and securely deleting quarantine entries are planned next.")
    "vulnerability" -> tr(fa, "این ماژول هنوز نتیجه آسیب‌پذیری واقعی تولید نمی‌کند. مرحله بعدی شامل شناسایی SDKها و کتابخانه‌ها و تطبیق آن‌ها با منابع CVE معتبر است.", "This module does not yet produce real vulnerability findings. Next steps include SDK and library inventory with mapping to trusted CVE sources.")
    "phishing" -> tr(fa, "بررسی امن URL با فهرست اعتبار و تحلیل دامنه هنوز به این نسخه متصل نشده است. هیچ لینک یا پیام در پس‌زمینه خوانده نمی‌شود.", "URL reputation and domain analysis are not connected yet. No links or messages are read in the background.")
    "network" -> tr(fa, "محافظ شبکه هنوز فعال نیست. پیاده‌سازی آن به طراحی شفاف VPN محلی/DNS و بررسی سیاست‌های Android و Google Play نیاز دارد.", "Network protection is not active. Implementation requires a transparent local VPN/DNS design and Android/Google Play policy review.")
    "brain" -> tr(fa, "فعلاً گزارش بر اساس قواعد محدود و شواهد قابل مشاهده ساخته می‌شود. امتیاز ریسک چندموتوره و مدل هوش مصنوعی هنوز به موتور اسکن وصل نشده است.", "Reports currently use limited, visible rules and evidence. Multi-engine risk scoring and AI reasoning are not yet connected to the scanner.")
    "selfdefense" -> tr(fa, "برنامه از پیکربندی‌های پایه مانند عدم اجازه اتصال cleartext و غیرفعال‌بودن backup استفاده می‌کند. بررسی یکپارچگی زمان اجرا و دفاع در برابر دست‌کاری هنوز نیازمند توسعه و آزمون است.", "The app has baseline controls such as cleartext traffic being disabled and backup disabled. Runtime integrity monitoring and anti-tamper defenses still require implementation and testing.")
    "permissions" -> tr(fa, "اسکن فایل از انتخاب‌گر رسمی Android استفاده می‌کند. در این نسخه مجوز اسکن کامل برنامه‌های نصب‌شده، Accessibility، روت یا دسترسی به داده خصوصی برنامه‌های دیگر درخواست نمی‌شود.", "File scanning uses Android's document picker. This build does not request broad installed-app inventory, Accessibility, root or access to other apps' private data.")
    else -> tr(fa, "کانال پشتیبانی رسمی پیش از عرضه عمومی به برنامه اضافه می‌شود. در این نسخه نشانی پشتیبانی تأییدشده‌ای تعریف نشده است.", "An official support channel will be added before public release. No verified support address is configured in this build.")
}

private fun tr(fa: Boolean, persian: String, english: String): String =
    if (fa) persian else english

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return "%.1f KB".format(kb)
    return "%.2f MB".format(kb / 1024.0)
}

package com.antivirusalai

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
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
private val Accent = Color(0xFF39D7CF)
private val Muted = Color(0xFF9CB0C5)

@Composable
fun AntivirusApp() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var language by rememberSaveable { mutableStateOf("fa") }
    var scanning by remember { mutableStateOf(false) }
    var selectedUri by remember { mutableStateOf<Uri?>(null) }
    var scanResult by remember { mutableStateOf<ScanResult?>(null) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var notice by remember { mutableStateOf<String?>(null) }
    var showDeleteInfo by remember { mutableStateOf(false) }
    val fa = language == "fa"

    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            selectedUri = uri
            scanning = true
            scanResult = null
            errorMessage = null
            notice = null
            scope.launch {
                try {
                    scanResult = ScanEngine.scan(context.applicationContext, uri)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    errorMessage = if (error is ScanTooLargeException) {
                        if (fa) "حجم فایل از سقف ۲۰۰ مگابایت بیشتر است." else error.message
                    } else {
                        error.message ?: if (fa) "اسکن انجام نشد." else "Scan failed."
                    }
                } finally {
                    scanning = false
                }
            }
        }
    }

    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Accent,
            onPrimary = Background,
            background = Background,
            surface = Panel,
            onSurface = Color(0xFFEAF2FA),
            secondary = Color(0xFF83A7C8)
        )
    ) {
        Surface(modifier = Modifier.fillMaxSize(), color = Background) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text(
                            "ANTIVIRUS AL AI",
                            color = Color.White,
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            if (fa) "محافظت هوشمند، شفاف و حریم‌خصوصی‌محور"
                            else "Transparent, privacy-first protection",
                            color = Muted,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    OutlinedButton(
                        onClick = { language = if (fa) "en" else "fa" },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Accent)
                    ) {
                        Text(if (fa) "EN" else "فا")
                    }
                }

                Card(
                    shape = RoundedCornerShape(22.dp),
                    colors = CardDefaults.cardColors(containerColor = Panel)
                ) {
                    Column(
                        Modifier.padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text(
                            if (fa) "اسکن فایل یا APK" else "Scan a file or APK",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            if (fa) {
                                "فقط فایلی که خودت انتخاب می‌کنی بررسی می‌شود. فایل اجرا یا نصب نمی‌شود و در این نسخه چیزی به سرور ارسال نمی‌شود."
                            } else {
                                "Only the file you select is inspected. It is never executed or installed, and this version uploads nothing."
                            },
                            color = Muted,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Button(
                            onClick = { picker.launch(arrayOf("*/*")) },
                            enabled = !scanning,
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = Accent)
                        ) {
                            Text(
                                if (scanning) {
                                    if (fa) "در حال اسکن..." else "Scanning..."
                                } else {
                                    if (fa) "انتخاب فایل برای اسکن" else "Choose file to scan"
                                }
                            )
                        }
                        if (scanning) {
                            LinearProgressIndicator(
                                modifier = Modifier.fillMaxWidth(),
                                color = Accent
                            )
                        }
                    }
                }

                errorMessage?.let {
                    InfoCard(title = if (fa) "خطا" else "Error", body = it)
                }
                notice?.let {
                    InfoCard(title = if (fa) "وضعیت" else "Status", body = it)
                }
                scanResult?.let { result ->
                    ScanResultCard(
                        result = result,
                        fa = fa,
                        onQuarantine = {
                            val uri = selectedUri
                            if (uri != null) {
                                scope.launch {
                                    try {
                                        val receipt = QuarantineManager.saveEncryptedCopy(
                                            context.applicationContext,
                                            uri,
                                            result.sha256
                                        )
                                        notice = if (fa) {
                                            "نسخه رمزنگاری‌شده در فضای خصوصی برنامه ذخیره شد. شناسه: ${receipt.id.take(8)}. فایل اصلی در محل قبلی باقی مانده و خودکار حذف نشده است."
                                        } else {
                                            "An encrypted copy was saved in private app storage. ID: ${receipt.id.take(8)}. The original remains in its original location."
                                        }
                                    } catch (cancelled: CancellationException) {
                                        throw cancelled
                                    } catch (error: Exception) {
                                        notice = error.message ?: if (fa) "قرنطینه انجام نشد." else "Quarantine failed."
                                    }
                                }
                            }
                        },
                        onUninstall = { packageName ->
                            try {
                                context.startActivity(
                                    Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName"))
                                )
                            } catch (_: Exception) {
                                notice = if (fa) {
                                    "صفحه حذف برنامه در این دستگاه در دسترس نیست."
                                } else {
                                    "Android's uninstall screen could not be opened."
                                }
                            }
                        },
                        onDeleteInfo = { showDeleteInfo = true }
                    )
                }

                Text(
                    if (fa) {
                        "نسخه اولیه: موتور امضای تولیدی و بانک ابری تهدید هنوز متصل نشده‌اند. نتیجه «بدون نشانگر شناخته‌شده» به معنی تضمین ایمنی نیست."
                    } else {
                        "Early build: production signatures and cloud threat feeds are not connected. “No known indicator” is not a safety guarantee."
                    },
                    color = Muted,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }

    if (showDeleteInfo) {
        AlertDialog(
            onDismissRequest = { showDeleteInfo = false },
            title = { Text(if (fa) "حذف فایل اصلی" else "Delete original file") },
            text = {
                Text(
                    if (fa) {
                        "این نسخه فقط نسخه رمزنگاری‌شده را ذخیره می‌کند و فایل اصلی را حذف نمی‌کند. برای جلوگیری از حذف اشتباه فایل سالم، فایل اصلی را فقط پس از بررسی مستقل و از برنامه مدیریت فایل حذف کن."
                    } else {
                        "This build stores an encrypted copy but does not delete the original. To avoid removing a legitimate file by mistake, delete the original only after independent review, using your file manager."
                    }
                )
            },
            confirmButton = {
                Button(onClick = { showDeleteInfo = false }) {
                    Text(if (fa) "متوجه شدم" else "Got it")
                }
            }
        )
    }
}

@Composable
private fun ScanResultCard(
    result: ScanResult,
    fa: Boolean,
    onQuarantine: () -> Unit,
    onUninstall: (String) -> Unit,
    onDeleteInfo: () -> Unit
) {
    val title = when (result.verdict) {
        ScanVerdict.TEST_MARKER_MATCH -> if (fa) "نشانگر آزمایشی بی‌خطر شناسایی شد" else "Benign test marker matched"
        ScanVerdict.SUSPICIOUS -> if (fa) "نیازمند بررسی بیشتر" else "Needs further review"
        ScanVerdict.NO_KNOWN_INDICATOR -> if (fa) "نشانگر شناخته‌شده‌ای پیدا نشد" else "No known indicator found"
        ScanVerdict.UNKNOWN_APK -> if (fa) "نتیجه نامشخص" else "Unknown result"
    }
    val description = when (result.verdict) {
        ScanVerdict.TEST_MARKER_MATCH -> if (fa) "این فقط فایل آزمایشی خود پروژه است؛ بدافزار نیست." else "This is the harmless project test fixture, not malware."
        ScanVerdict.SUSPICIOUS -> if (fa) "چند نشانه ایستا دیده شده است. این نتیجه اثبات بدافزار بودن نیست." else "Static indicators were found. This is not proof of malware."
        ScanVerdict.NO_KNOWN_INDICATOR -> if (fa) "هیچ نشانگر موجود در نسخه فعلی با فایل تطبیق نکرد. این نتیجه تضمین پاک بودن نیست." else "No indicator in this MVP matched. This does not guarantee the file is clean."
        ScanVerdict.UNKNOWN_APK -> if (fa) "اطلاعات APK قابل خواندن نبود؛ از اعلام پاک بودن خودداری می‌کنیم." else "APK metadata could not be read; the file is not being declared clean."
    }

    Card(shape = RoundedCornerShape(22.dp), colors = CardDefaults.cardColors(containerColor = Panel)) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(if (fa) "گزارش اسکن" else "Scan report", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(result.displayName, color = Color.White, fontWeight = FontWeight.SemiBold)
            Text(
                title,
                color = if (result.verdict == ScanVerdict.SUSPICIOUS) Color(0xFFFFC46B) else Accent,
                fontWeight = FontWeight.Bold
            )
            Text(description, color = Muted)
            Text(
                "${if (fa) "حجم" else "Size"}: ${formatBytes(result.sizeBytes)}  •  ${if (fa) "زمان" else "Time"}: ${result.durationMillis} ms",
                color = Muted,
                style = MaterialTheme.typography.bodySmall
            )
            Text("SHA-256", color = Color.White, fontWeight = FontWeight.SemiBold)
            Text(result.sha256, color = Muted, style = MaterialTheme.typography.bodySmall)

            result.apkMetadata?.let { apk ->
                Spacer(Modifier.height(4.dp))
                Text(if (fa) "اطلاعات APK" else "APK metadata", color = Color.White, fontWeight = FontWeight.SemiBold)
                Text("Package: ${apk.packageName}", color = Muted, style = MaterialTheme.typography.bodySmall)
                Text("Target SDK: ${apk.targetSdk}", color = Muted, style = MaterialTheme.typography.bodySmall)
                Text(
                    if (fa) "مجوزهای درخواستی: ${apk.requestedPermissions.size}"
                    else "Requested permissions: ${apk.requestedPermissions.size}",
                    color = Muted,
                    style = MaterialTheme.typography.bodySmall
                )
                apk.signingCertificateSha256?.let {
                    Text("Signer SHA-256: $it", color = Muted, style = MaterialTheme.typography.bodySmall)
                }
            }

            Text(if (fa) "شواهد" else "Evidence", color = Color.White, fontWeight = FontWeight.SemiBold)
            result.evidence.forEach { item ->
                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(
                        "${item.title} · ${item.severity.name}",
                        color = if (item.severity == EvidenceSeverity.HIGH) Color(0xFFFFC46B) else Color.White,
                        fontWeight = FontWeight.Medium
                    )
                    Text(item.detail, color = Muted, style = MaterialTheme.typography.bodySmall)
                }
            }

            Button(
                onClick = onQuarantine,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Accent)
            ) {
                Text(if (fa) "ذخیره نسخه رمزنگاری‌شده در قرنطینه" else "Save encrypted copy to quarantine")
            }
            result.apkMetadata?.let { apk ->
                OutlinedButton(onClick = { onUninstall(apk.packageName) }, modifier = Modifier.fillMaxWidth()) {
                    Text(if (fa) "باز کردن صفحه حذف برنامه در Android" else "Open Android uninstall screen")
                }
            }
            OutlinedButton(onClick = onDeleteInfo, modifier = Modifier.fillMaxWidth()) {
                Text(if (fa) "درباره حذف فایل اصلی" else "About deleting the original")
            }
        }
    }
}

@Composable
private fun InfoCard(title: String, body: String) {
    Card(shape = RoundedCornerShape(16.dp), colors = CardDefaults.cardColors(containerColor = Panel)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, color = Color.White, fontWeight = FontWeight.SemiBold)
            Text(body, color = Muted)
        }
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return "%.1f KB".format(kb)
    return "%.2f MB".format(kb / 1024.0)
}

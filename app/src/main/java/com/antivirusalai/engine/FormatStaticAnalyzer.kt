package com.antivirusalai.engine

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Enumeration
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

data class StaticAnalysisReport(
    val format: String?,
    val supported: Boolean,
    val complete: Boolean,
    val entryCount: Int,
    val expandedBytes: Long,
    val evidence: List<ScanEvidence>,
    val signalCategories: Set<String>,
    val riskPoints: Int
)

object FormatStaticAnalyzer {
    private const val MAX_ENTRIES = 2_000
    private const val MAX_ENTRY_BYTES = 32L * 1024L * 1024L
    private const val MAX_NESTED_ARCHIVE_BYTES = 8L * 1024L * 1024L
    private const val MAX_EXPANDED_BYTES = 128L * 1024L * 1024L
    private const val MAX_DEX_BYTES = 64L * 1024L * 1024L
    private const val MAX_DEX_FILES = 32
    private const val MAX_NESTED_DEPTH = 2
    private const val MAX_COMPRESSION_RATIO = 200L

    private data class Budget(
        var entries: Int = 0,
        var expanded: Long = 0L,
        var dexBytes: Long = 0L,
        var dexFiles: Int = 0,
        var complete: Boolean = true
    )

    private data class ApiSignal(
        val needle: String,
        val code: String,
        val title: String,
        val detail: String,
        val category: String,
        val points: Int
    )

    private val dexSignals = listOf(
        ApiSignal("android/telephony/SmsManager", "DEX_SMS_API_REFERENCE", "SMS API reference",
            "DEX contains a reference to Android SMS APIs. A reference alone does not prove that the API is invoked.", "SENSITIVE_API", 2),
        ApiSignal("android/content/pm/PackageInstaller", "DEX_PACKAGE_INSTALL_API", "Package installation API reference",
            "DEX contains a reference to package-installation APIs. Legitimate installers may use this capability.", "INSTALL_API", 2),
        ApiSignal("dalvik/system/DexClassLoader", "DEX_DYNAMIC_CODE_LOADING", "Dynamic code-loading API reference",
            "DEX contains a reference to dynamic code loading. The source and integrity of downloaded code require review.", "DYNAMIC_CODE", 3),
        ApiSignal("java/lang/ProcessBuilder", "DEX_PROCESS_BUILDER_API", "Process execution API reference",
            "DEX contains a reference to ProcessBuilder. This is a capability indicator, not proof of execution.", "PROCESS_EXECUTION", 3),
        ApiSignal("java/lang/Runtime", "DEX_RUNTIME_API", "Runtime API reference",
            "DEX contains a reference to Runtime APIs. Additional context is required to determine whether process execution is used.", "PROCESS_EXECUTION", 1),
        ApiSignal("android/accessibilityservice/AccessibilityService", "DEX_ACCESSIBILITY_API", "Accessibility API reference",
            "DEX references Android accessibility-service APIs. This can be legitimate assistive functionality.", "ACCESSIBILITY", 2),
        ApiSignal("android/app/admin/DeviceAdminReceiver", "DEX_DEVICE_ADMIN_API", "Device administration API reference",
            "DEX references device-administration APIs. Review the app's stated purpose and user consent.", "DEVICE_ADMIN", 2),
        ApiSignal("java/net/Socket", "DEX_SOCKET_API", "Socket API reference",
            "DEX references low-level socket APIs. This does not establish malicious network activity.", "NETWORK_API", 1)
    )

    private val elfSignals = listOf(
        ApiSignal("execve", "ELF_EXECVE_SYMBOL", "Native process-execution symbol",
            "ELF strings contain an execve symbol reference. Static symbol presence is not proof of execution.", "NATIVE_EXECUTION", 3),
        ApiSignal("system", "ELF_SYSTEM_SYMBOL", "Native system symbol",
            "ELF strings contain a system symbol reference. Additional code context is required.", "NATIVE_EXECUTION", 2),
        ApiSignal("ptrace", "ELF_PTRACE_SYMBOL", "Native process-inspection symbol",
            "ELF strings contain a ptrace symbol reference. This can have legitimate debugging uses.", "NATIVE_INSPECTION", 2),
        ApiSignal("dlopen", "ELF_DLOPEN_SYMBOL", "Dynamic library loading symbol",
            "ELF strings contain a dlopen symbol reference. Review dynamic-library loading behavior and provenance.", "DYNAMIC_CODE", 2)
    )

    fun analyze(file: File): StaticAnalysisReport {
        val evidence = mutableListOf<ScanEvidence>()
        val categories = linkedSetOf<String>()
        val budget = Budget()
        var riskPoints = 0
        val header = ByteArray(8)
        val headerSize = runCatching { file.inputStream().use { it.read(header) } }.getOrDefault(-1)
        if (headerSize >= 4 && header[0] == 0x7f.toByte() && header[1] == 'E'.code.toByte() &&
            header[2] == 'L'.code.toByte() && header[3] == 'F'.code.toByte()
        ) {
            analyzeElfBytes(file, evidence, categories).also { riskPoints += it }
            val complete = file.length() <= 8L * 1024L * 1024L
            if (!complete) {
                evidence += ScanEvidence(
                    "ELF_PREFIX_LIMIT", "ELF analysis used a bounded prefix",
                    "Only the first 8 MiB of this native file were inspected; later sections were not covered.",
                    EvidenceSeverity.INFO
                )
            }
            return StaticAnalysisReport("ELF", true, complete, 0, minOf(file.length(), 8L * 1024L * 1024L), evidence, categories, riskPoints)
        }
        if (headerSize >= 4 && header[0] == 'P'.code.toByte() && header[1] == 'K'.code.toByte()) {
            var isApkContainer = false
            try {
                isApkContainer = ZipFile(file).use { zip ->
                    val apkContainer = zip.getEntry("AndroidManifest.xml") != null
                    scanZipFile(zip, budget, evidence, categories)
                    apkContainer
                }
            } catch (error: Exception) {
                budget.complete = false
                evidence += ScanEvidence(
                    "ARCHIVE_PARSE_FAILED", "Archive parsing incomplete",
                    "The ZIP container could not be fully parsed: ${error.javaClass.simpleName}. No clean conclusion is drawn.",
                    EvidenceSeverity.MEDIUM
                )
            }
            riskPoints += scoreCategories(categories)
            return StaticAnalysisReport(
                if (isApkContainer) "APK" else "ZIP",
                true, budget.complete, budget.entries, budget.expanded, evidence, categories, riskPoints
            )
        }
        return StaticAnalysisReport(null, false, true, 0, 0L, emptyList(), emptySet(), 0)
    }

    private fun scanZipFile(
        zip: ZipFile,
        budget: Budget,
        evidence: MutableList<ScanEvidence>,
        categories: MutableSet<String>
    ) {
        val entries = zip.entries()
        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            if (!registerEntry(entry.name, entry.size, entry.compressedSize, budget, evidence, categories)) {
                if (!budget.complete) break
                continue
            }
            val lower = entry.name.lowercase()
            val isDex = Regex("(^|/)classes[0-9]*\\.dex$").containsMatchIn(lower)
            val isNative = lower.endsWith(".so")
            val mayBeNested = lower.endsWith(".zip") || lower.endsWith(".jar") || lower.endsWith(".apk")
            if (!isDex && !isNative && !mayBeNested) continue
            val limit = when {
                isDex -> MAX_ENTRY_BYTES
                mayBeNested -> MAX_NESTED_ARCHIVE_BYTES
                else -> 8L * 1024L * 1024L
            }
            val bytes = try {
                zip.getInputStream(entry).use { readBounded(it, limit, budget) }
            } catch (_: LimitExceeded) {
                budget.complete = false
                evidence += ScanEvidence(
                    "ARCHIVE_ENTRY_LIMIT", "Archive entry exceeded analysis limits",
                    "An entry was skipped because its expanded size exceeded the configured safety ceiling. The archive scan stopped safely.",
                    EvidenceSeverity.MEDIUM
                )
                break
            }
            inspectEntryBytes(entry.name, bytes, 0, budget, evidence, categories)
        }
    }

    private fun scanNestedZip(
        bytes: ByteArray,
        depth: Int,
        budget: Budget,
        evidence: MutableList<ScanEvidence>,
        categories: MutableSet<String>
    ) {
        if (depth > MAX_NESTED_DEPTH) {
            budget.complete = false
            categories += "ARCHIVE_ANOMALY"
            evidence += ScanEvidence(
                "NESTED_ARCHIVE_DEPTH_LIMIT", "Nested archive depth limit reached",
                "An archive nested deeper than the configured limit was not expanded.",
                EvidenceSeverity.MEDIUM
            )
            return
        }
        ZipInputStream(ByteArrayInputStream(bytes)).use { input ->
            while (true) {
                val entry = input.nextEntry ?: break
                if (!registerEntry(entry.name, entry.size, entry.compressedSize, budget, evidence, categories)) {
                    // Do not advance ZipInputStream after a rejected entry: nextEntry/closeEntry
                    // may drain and decompress the rejected entry without our byte counter.
                    break
                }
                val lower = entry.name.lowercase()
                val isDex = Regex("(^|/)classes[0-9]*\\.dex$").containsMatchIn(lower)
                val isNative = lower.endsWith(".so")
                val nested = lower.endsWith(".zip") || lower.endsWith(".jar") || lower.endsWith(".apk")
                val limit = when {
                    nested -> MAX_NESTED_ARCHIVE_BYTES
                    isDex -> MAX_ENTRY_BYTES
                    else -> 8L * 1024L * 1024L
                }
                val extracted = try {
                    // Read every nested entry through the same bounded counter, including
                    // entries that are not structurally interesting to this scanner.
                    readBounded(input, limit, budget)
                } catch (_: LimitExceeded) {
                    budget.complete = false
                    evidence += ScanEvidence(
                        "NESTED_ENTRY_LIMIT", "Nested archive entry exceeded limits",
                        "A nested entry was not fully inspected because of its configured size ceiling. The nested archive scan stopped safely.",
                        EvidenceSeverity.MEDIUM
                    )
                    break
                }
                if (isDex || isNative || nested) {
                    inspectEntryBytes(entry.name, extracted, depth, budget, evidence, categories)
                }
                input.closeEntry()
            }
        }
    }

    private fun registerEntry(
        name: String,
        size: Long,
        compressedSize: Long,
        budget: Budget,
        evidence: MutableList<ScanEvidence>,
        categories: MutableSet<String>
    ): Boolean {
        budget.entries++
        if (budget.entries > MAX_ENTRIES) {
            budget.complete = false
            evidence += ScanEvidence(
                "ARCHIVE_ENTRY_COUNT_LIMIT", "Archive entry-count limit reached",
                "Analysis stopped after $MAX_ENTRIES entries to prevent resource exhaustion.",
                EvidenceSeverity.MEDIUM
            )
            return false
        }
        val normalized = name.replace('\\', '/')
        if (normalized.startsWith("/") || normalized.split('/').any { it == ".." }) {
            categories += "ARCHIVE_ANOMALY"
            evidence += ScanEvidence(
                "ARCHIVE_PATH_TRAVERSAL_NAME", "Unsafe archive path name",
                "The archive contains a path that attempts to escape its logical root. No entry is extracted to disk.",
                EvidenceSeverity.MEDIUM
            )
        }
        if (size > MAX_ENTRY_BYTES || size < -1L) {
            budget.complete = false
            return false
        }
        if (size > 0L && compressedSize > 0L && size / compressedSize.coerceAtLeast(1L) > MAX_COMPRESSION_RATIO) {
            categories += "ARCHIVE_ANOMALY"
            budget.complete = false
            evidence += ScanEvidence(
                "ARCHIVE_HIGH_COMPRESSION_RATIO", "High archive compression ratio",
                "An entry has an unusually high declared compression ratio. It is skipped rather than fully expanded.",
                EvidenceSeverity.MEDIUM
            )
            return false
        }
        if (size > 0L && size > MAX_EXPANDED_BYTES - budget.expanded) {
            budget.complete = false
            return false
        }
        return true
    }

    private fun readBounded(input: InputStream, perEntryLimit: Long, budget: Budget): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var entryBytes = 0L
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            val nextEntryBytes = entryBytes + count
            if (nextEntryBytes > perEntryLimit || count.toLong() > MAX_EXPANDED_BYTES - budget.expanded) {
                throw LimitExceeded()
            }
            entryBytes = nextEntryBytes
            budget.expanded += count
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun inspectEntryBytes(
        name: String,
        bytes: ByteArray,
        depth: Int,
        budget: Budget,
        evidence: MutableList<ScanEvidence>,
        categories: MutableSet<String>
    ) {
        val lower = name.lowercase()
        if (Regex("(^|/)classes[0-9]*\\.dex$").containsMatchIn(lower) || bytes.startsWithAscii("dex\n")) {
            budget.dexFiles++
            budget.dexBytes += bytes.size
            if (budget.dexFiles > MAX_DEX_FILES || budget.dexBytes > MAX_DEX_BYTES) {
                budget.complete = false
                evidence += ScanEvidence(
                    "DEX_ANALYSIS_LIMIT", "DEX analysis limit reached",
                    "The APK contains more DEX data than the configured analysis budget allows.",
                    EvidenceSeverity.MEDIUM
                )
                return
            }
            analyzeDex(bytes, evidence, categories)
        } else if (bytes.startsWithElf()) {
            riskPointsForElf(bytes, evidence, categories)
        } else if (bytes.startsWithZip()) {
            scanNestedZip(bytes, depth + 1, budget, evidence, categories)
        }
    }

    private fun analyzeDex(
        bytes: ByteArray,
        evidence: MutableList<ScanEvidence>,
        categories: MutableSet<String>
    ) {
        if (bytes.size < 0x70 || !bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(0x64, 0x65, 0x78, 0x0a))) {
            evidence += ScanEvidence(
                "DEX_HEADER_INVALID", "DEX header is invalid",
                "A file named as DEX data does not contain the expected minimum DEX header.",
                EvidenceSeverity.MEDIUM
            )
            categories += "FORMAT_ANOMALY"
            return
        }
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val declaredSize = buffer.getInt(32).toLong() and 0xffffffffL
        val headerSize = buffer.getInt(36)
        val endianTag = buffer.getInt(40)
        if (declaredSize != bytes.size.toLong() || headerSize != 0x70 || endianTag != 0x12345678) {
            evidence += ScanEvidence(
                "DEX_HEADER_INCONSISTENT", "DEX header fields are inconsistent",
                "The DEX file size, header size, or endian tag does not match the bounded entry data.",
                EvidenceSeverity.MEDIUM
            )
            categories += "FORMAT_ANOMALY"
        }
        for (signal in dexSignals) {
            if (bytes.containsAscii(signal.needle)) {
                evidence += ScanEvidence(signal.code, signal.title, signal.detail, EvidenceSeverity.LOW)
                categories += signal.category
            }
        }
    }

    private fun analyzeElfBytes(
        file: File,
        evidence: MutableList<ScanEvidence>,
        categories: MutableSet<String>
    ): Int {
        val bytes = runCatching {
            file.inputStream().use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var remaining = 8L * 1024L * 1024L
                while (remaining > 0L) {
                    val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                    if (count < 0) break
                    output.write(buffer, 0, count)
                    remaining -= count
                }
                output.toByteArray()
            }
        }.getOrDefault(byteArrayOf())
        return riskPointsForElf(bytes, evidence, categories)
    }

    private fun riskPointsForElf(
        bytes: ByteArray,
        evidence: MutableList<ScanEvidence>,
        categories: MutableSet<String>
    ): Int {
        if (!bytes.startsWithElf() || bytes.size < 20) {
            evidence += ScanEvidence(
                "ELF_HEADER_INVALID", "ELF header is invalid",
                "The native library has an invalid or truncated ELF header.",
                EvidenceSeverity.MEDIUM
            )
            categories += "FORMAT_ANOMALY"
            return 0
        }
        val elfClass = bytes[4].toInt() and 0xff
        val data = bytes[5].toInt() and 0xff
        val machine = if (data == 2) {
            ((bytes[18].toInt() and 0xff) shl 8) or (bytes[19].toInt() and 0xff)
        } else {
            (bytes[18].toInt() and 0xff) or ((bytes[19].toInt() and 0xff) shl 8)
        }
        if (elfClass !in 1..2 || data !in 1..2 || machine == 0) {
            evidence += ScanEvidence(
                "ELF_HEADER_FIELDS_INVALID", "ELF header fields are invalid",
                "The ELF class, byte order, or machine field is not valid.",
                EvidenceSeverity.MEDIUM
            )
            categories += "FORMAT_ANOMALY"
        } else {
            evidence += ScanEvidence(
                "ELF_FORMAT_IDENTIFIED", "Native ELF file identified",
                "ELF class $elfClass, machine $machine. Native code is inspected statically only; it is never loaded or executed.",
                EvidenceSeverity.INFO
            )
        }
        var points = 0
        for (signal in elfSignals) {
            if (bytes.containsAscii(signal.needle)) {
                evidence += ScanEvidence(signal.code, signal.title, signal.detail, EvidenceSeverity.LOW)
                categories += signal.category
                points += signal.points
            }
        }
        return points
    }

    private fun scoreCategories(categories: Set<String>): Int =
        categories.sumOf { category ->
            when (category) {
                "DYNAMIC_CODE" -> 3
                "PROCESS_EXECUTION", "NATIVE_EXECUTION" -> 3
                "ARCHIVE_ANOMALY", "FORMAT_ANOMALY" -> 2
                "SENSITIVE_API", "INSTALL_API", "ACCESSIBILITY", "DEVICE_ADMIN" -> 2
                else -> 1
            }
        }

    private fun ByteArray.startsWithAscii(value: String): Boolean =
        size >= value.length && value.indices.all { this[it] == value[it].code.toByte() }

    private fun ByteArray.startsWithElf(): Boolean =
        size >= 4 && this[0] == 0x7f.toByte() && this[1] == 0x45.toByte() &&
            this[2] == 0x4c.toByte() && this[3] == 0x46.toByte()

    private fun ByteArray.startsWithZip(): Boolean =
        size >= 4 && this[0] == 0x50.toByte() && this[1] == 0x4b.toByte()

    private fun ByteArray.containsAscii(value: String): Boolean {
        val pattern = value.toByteArray(Charsets.US_ASCII)
        if (pattern.isEmpty() || pattern.size > size) return false
        outer@ for (i in 0..size - pattern.size) {
            for (j in pattern.indices) if (this[i + j] != pattern[j]) continue@outer
            return true
        }
        return false
    }

    private class LimitExceeded : Exception()
}

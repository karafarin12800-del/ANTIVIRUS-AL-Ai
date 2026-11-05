package com.antivirusalai.engine

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

class ScanTooLargeException(message: String) : Exception(message)

object ScanEngine {
    const val MAX_FILE_SIZE_BYTES = 200L * 1024L * 1024L

    suspend fun scan(context: Context, uri: Uri): ScanResult = withContext(Dispatchers.IO) {
        val resolver = context.contentResolver
        val localFile = if (uri.scheme == "file") uri.path?.let(::File) else null
        val metadata = if (localFile != null) {
            localFile.name to localFile.length()
        } else {
            resolver.query(
                uri,
                arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                null, null, null
            )?.use { cursor ->
                if (!cursor.moveToFirst()) null else {
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                    val name = if (nameIndex >= 0) cursor.getString(nameIndex) else null
                    val size = if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) cursor.getLong(sizeIndex) else -1L
                    name to size
                }
            }
        }

        val displayName = metadata?.first?.takeIf { it.isNotBlank() } ?: "Selected file"
        val declaredSize = metadata?.second ?: -1L
        if (declaredSize > MAX_FILE_SIZE_BYTES) {
            throw ScanTooLargeException("File exceeds the 200 MB MVP scan limit.")
        }

        val mimeType = resolver.getType(uri)
        val temp = File.createTempFile("alai-scan-", ".bin", context.cacheDir)
        val digest = MessageDigest.getInstance("SHA-256")
        var totalBytes = 0L
        val startedAt = System.nanoTime()

        try {
            val input = resolver.openInputStream(uri)
                ?: throw IllegalStateException("Android could not open the selected file.")

            input.use { source ->
                FileOutputStream(temp).use { sink ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = source.read(buffer)
                        if (count < 0) break
                        totalBytes += count
                        if (totalBytes > MAX_FILE_SIZE_BYTES) {
                            throw ScanTooLargeException("File exceeds the 200 MB MVP scan limit.")
                        }
                        digest.update(buffer, 0, count)
                        sink.write(buffer, 0, count)
                    }
                    sink.fd.sync()
                }
            }

            val hash = digest.digest().joinToString("") {
                "%02x".format(it.toInt() and 0xff)
            }
            val evidence = mutableListOf<ScanEvidence>()
            val localMatch = LocalIndicatorDatabase.lookup(hash)
            val looksLikeApk = ApkFileDetector.isApkArchive(temp) ||
                displayName.endsWith(".apk", ignoreCase = true) ||
                mimeType == "application/vnd.android.package-archive"
            val apk = if (looksLikeApk) ApkMetadataInspector.inspect(context, temp) else null
            val codeAnalysis = if (!looksLikeApk && SourceCodeAnalyzer.supports(displayName)) {
                if (totalBytes > SourceCodeAnalyzer.MAX_SOURCE_BYTES) {
                    SourceCodeAnalyzer.limitedReport(displayName)
                } else {
                    runCatching {
                        SourceCodeAnalyzer.analyze(displayName, temp.readText(Charsets.UTF_8))
                    }.getOrElse {
                        val detectedLanguage = SourceCodeAnalyzer.languageFor(displayName) ?: "Unknown"
                        CodeAnalysisReport(
                            language = detectedLanguage,
                            lineCount = 0,
                            diagnostics = emptyList(),
                            completed = false,
                            limitationFa = "فایل خوانده شد اما متن آن برای تحلیل قابل رمزگشایی نبود.",
                            limitationEn = "The file was read, but its text could not be decoded for static analysis."
                        )
                    }
                }
            } else null

            val verdict = when {
                localMatch != null -> {
                    evidence += ScanEvidence(
                        "BENIGN_PROJECT_TEST_MARKER",
                        "Benign project test marker matched",
                        "This is a harmless ANTIVIRUS AL AI test fixture used only to validate hashing and reporting. It is not malware.",
                        EvidenceSeverity.INFO
                    )
                    ScanVerdict.TEST_MARKER_MATCH
                }
                looksLikeApk && apk == null -> {
                    evidence += ScanEvidence(
                        "APK_PARSE_UNAVAILABLE",
                        "APK metadata could not be parsed",
                        "The selected file looks like an APK, but Android's package parser could not read its metadata. The result is unknown, not clean.",
                        EvidenceSeverity.MEDIUM
                    )
                    ScanVerdict.UNKNOWN_APK
                }
                apk != null -> {
                    val assessment = PermissionRiskAnalyzer.analyze(apk)
                    evidence += assessment.evidence
                    if (assessment.suspicious) ScanVerdict.SUSPICIOUS
                    else ScanVerdict.NO_KNOWN_INDICATOR
                }
                codeAnalysis != null && !codeAnalysis.completed -> {
                    evidence += ScanEvidence(
                        "CODE_ANALYSIS_LIMITED",
                        "Source-code analysis was limited",
                        codeAnalysis.limitationEn ?: "Static analysis could not be completed.",
                        EvidenceSeverity.INFO
                    )
                    ScanVerdict.CODE_ANALYSIS_LIMITED
                }
                codeAnalysis != null && codeAnalysis.actionableIssueCount > 0 -> {
                    evidence += ScanEvidence(
                        "CODE_STATIC_FINDINGS",
                        "Static source-code findings",
                        "${codeAnalysis.actionableIssueCount} actionable static finding(s) across ${codeAnalysis.diagnostics.size} diagnostic(s). Findings need manual review and do not prove exploitability.",
                        EvidenceSeverity.MEDIUM
                    )
                    ScanVerdict.CODE_ISSUES_FOUND
                }
                codeAnalysis != null -> {
                    evidence += ScanEvidence(
                        "CODE_STATIC_ANALYSIS_COMPLETE",
                        "Static source-code analysis completed",
                        "No high-priority structural or security pattern was detected by the current lightweight rules. This is not a proof of correctness or security.",
                        EvidenceSeverity.INFO
                    )
                    ScanVerdict.CODE_ANALYZED
                }
                else -> {
                    evidence += ScanEvidence(
                        "NO_LOCAL_HASH_MATCH",
                        "File type not covered by the current scanner",
                        "This MVP does not yet perform content or format-aware malware analysis for this file type. It must be treated as unknown, not clean.",
                        EvidenceSeverity.INFO
                    )
                    ScanVerdict.UNSUPPORTED_FILE
                }
            }

            ScanResult(
                displayName = displayName,
                mimeType = mimeType,
                sizeBytes = totalBytes,
                sha256 = hash,
                verdict = verdict,
                evidence = evidence,
                apkMetadata = apk,
                durationMillis = (System.nanoTime() - startedAt) / 1_000_000L,
                codeAnalysis = codeAnalysis
            )
        } finally {
            temp.delete()
        }
    }
}

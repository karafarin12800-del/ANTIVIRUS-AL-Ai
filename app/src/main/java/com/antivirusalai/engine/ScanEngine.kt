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
import com.antivirusalai.intel.ThreatClassification
import com.antivirusalai.intel.ThreatFeedFreshness
import com.antivirusalai.intel.ThreatFeedRuntime

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
        var nativeSession = NativeContentEngine.openSession()
        var contentEngineState = if (nativeSession == null) {
            ContentEngineState.UNAVAILABLE
        } else {
            ContentEngineState.INCOMPLETE
        }
        var contentEngineErrorCode: String? =
            if (nativeSession == null) "NATIVE_LIBRARY_UNAVAILABLE" else null
        var nativeSelfTestMatch = false

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
                        if (nativeSession != null && contentEngineErrorCode == null) {
                            try {
                                nativeSession?.update(buffer, count)
                            } catch (_: Exception) {
                                runCatching { nativeSession?.close() }
                                nativeSession = null
                                contentEngineState = ContentEngineState.INCOMPLETE
                                contentEngineErrorCode = "NATIVE_UPDATE_FAILED"
                            } catch (_: LinkageError) {
                                runCatching { nativeSession?.close() }
                                nativeSession = null
                                contentEngineState = ContentEngineState.INCOMPLETE
                                contentEngineErrorCode = "NATIVE_LINKAGE_FAILED"
                            }
                        }
                        sink.write(buffer, 0, count)
                    }
                    sink.fd.sync()
                }
            }

            if (nativeSession != null && contentEngineErrorCode == null) {
                try {
                    when (nativeSession!!.finish()) {
                        NativeContentEngine.RESULT_NO_MATCH -> Unit
                        NativeContentEngine.RESULT_SELF_TEST_MATCH -> nativeSelfTestMatch = true
                        else -> error("Native engine returned an unknown result code.")
                    }
                    contentEngineState = ContentEngineState.COMPLETE
                } catch (_: Exception) {
                    contentEngineState = ContentEngineState.INCOMPLETE
                    contentEngineErrorCode = "NATIVE_FINISH_FAILED"
                } catch (_: LinkageError) {
                    contentEngineState = ContentEngineState.INCOMPLETE
                    contentEngineErrorCode = "NATIVE_LINKAGE_FAILED"
                }
            }

            val hash = digest.digest().joinToString("") {
                "%02x".format(it.toInt() and 0xff)
            }
            val evidence = mutableListOf<ScanEvidence>()
            if (contentEngineState != ContentEngineState.COMPLETE) {
                evidence += ScanEvidence(
                    "NATIVE_CONTENT_ENGINE_INCOMPLETE",
                    "Native content analysis is unavailable or incomplete",
                    "The local C++ stream matcher did not complete. Its result is not used as evidence of a clean file.",
                    EvidenceSeverity.INFO
                )
            }
            if (nativeSelfTestMatch) {
                evidence += ScanEvidence(
                    "NATIVE_ENGINE_SELF_TEST_MARKER",
                    "Harmless native-engine self-test marker matched",
                    "The C++ stream matcher recognized its dedicated harmless test fixture. This is an engine self-test, not a malware detection.",
                    EvidenceSeverity.INFO
                )
            }
            val localMatch = LocalIndicatorDatabase.lookup(hash)
            val eicarMatch = EicarTestDetector.contains(temp)
            val currentThreatFeed = ThreatFeedRuntime.currentFeed(context.applicationContext)
            val threatFeedStatus = ThreatFeedRuntime.status(context.applicationContext)
            val threatMatch = currentThreatFeed?.indicators?.get(hash.lowercase())
            if (currentThreatFeed?.truncated == true) {
                evidence += ScanEvidence(
                    "THREAT_FEED_TRUNCATED",
                    "Threat intelligence snapshot is capped",
                    "The signed feed reports that per-type indicator limits excluded some otherwise valid entries. A non-match is therefore not exhaustive.",
                    EvidenceSeverity.INFO
                )
            }
            if (threatFeedStatus.freshness != ThreatFeedFreshness.UP_TO_DATE) {
                val stale = threatFeedStatus.freshness == ThreatFeedFreshness.STALE
                evidence += ScanEvidence(
                    if (stale) "THREAT_FEED_STALE" else "THREAT_FEED_UNAVAILABLE",
                    "Current threat intelligence is not available",
                    if (stale) {
                        "The last authenticated threat feed has expired. This file cannot be given a current feed no-match result."
                    } else {
                        "No valid current authenticated threat feed is available. This file cannot be given a current feed no-match result."
                    },
                    EvidenceSeverity.INFO
                )
            }
            val looksLikeApk = ApkFileDetector.isApkArchive(temp) ||
                displayName.endsWith(".apk", ignoreCase = true) ||
                mimeType == "application/vnd.android.package-archive"
            val apk = if (looksLikeApk) ApkMetadataInspector.inspect(context, temp) else null

            val verdict = when {
                threatMatch?.classification == ThreatClassification.MALWARE -> {
                    evidence += ScanEvidence(
                        "SIGNED_FEED_KNOWN_MALWARE",
                        "Known malware hash match",
                        "Exact SHA-256 match in the current authenticated threat feed. Family: " +
                            threatMatch.familyId + ". This is a reputation match, not behavioral analysis.",
                        EvidenceSeverity.HIGH
                    )
                    ScanVerdict.KNOWN_MALWARE
                }
                threatMatch?.classification == ThreatClassification.PUA -> {
                    evidence += ScanEvidence(
                        "SIGNED_FEED_PUA",
                        "Potentially unwanted file hash match",
                        "Exact SHA-256 match in the current authenticated threat feed. Family: " +
                            threatMatch.familyId + ". Review the publisher and intended use before taking action.",
                        EvidenceSeverity.MEDIUM
                    )
                    ScanVerdict.POTENTIALLY_UNWANTED
                }
                threatMatch?.classification == ThreatClassification.SUSPICIOUS -> {
                    evidence += ScanEvidence(
                        "SIGNED_FEED_SUSPICIOUS",
                        "Suspicious file hash match",
                        "Exact SHA-256 match in the current authenticated threat feed. Family: " +
                            threatMatch.familyId + ". The source classifies this as suspicious, not confirmed malware.",
                        EvidenceSeverity.MEDIUM
                    )
                    ScanVerdict.SUSPICIOUS
                }
                eicarMatch -> {
                    evidence += ScanEvidence(
                        "EICAR_TEST_FILE",
                        "Harmless EICAR test string detected",
                        "The standard EICAR antivirus test string was detected. It is intentionally harmless and is used only to test scanner reporting.",
                        EvidenceSeverity.INFO
                    )
                    ScanVerdict.TEST_MARKER_MATCH
                }
                nativeSelfTestMatch -> ScanVerdict.TEST_MARKER_MATCH
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
                    when {
                        assessment.suspicious -> ScanVerdict.SUSPICIOUS
                        else -> {
                            evidence += ScanEvidence(
                                "APK_CONTENT_COVERAGE_NOT_ESTABLISHED",
                                "APK content coverage is not established",
                                "A non-empty hash feed only checks exact file reputation. The production APK/DEX content-rule set is not active, so a hash non-match cannot establish complete APK coverage.",
                                EvidenceSeverity.INFO
                            )
                            ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE
                        }
                    }
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
                contentEngineState = contentEngineState,
                contentRuleSetId = if (contentEngineState == ContentEngineState.UNAVAILABLE) {
                    null
                } else {
                    NativeContentEngine.RULE_SET_ID
                },
                contentRuleMatches = if (nativeSelfTestMatch) {
                    listOf(NativeContentEngine.SELF_TEST_RULE_ID)
                } else {
                    emptyList()
                },
                contentEngineErrorCode = contentEngineErrorCode
            )
        } finally {
            runCatching { nativeSession?.close() }
            temp.delete()
        }
    }
}

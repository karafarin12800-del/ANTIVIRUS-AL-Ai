package com.antivirusalai.engine

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.antivirusalai.intel.ContentRuleBundleRuntime
import com.antivirusalai.intel.ContentRuleBundleState
import com.antivirusalai.intel.ThreatClassification
import com.antivirusalai.intel.ThreatFeedFreshness
import com.antivirusalai.intel.ThreatFeedRuntime
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
        val contentBundle = ContentRuleBundleRuntime.current(context.applicationContext)
        var nativeSession = NativeContentEngine.openSession(contentBundle?.rules.orEmpty())
        var contentEngineState = if (nativeSession == null) ContentEngineState.UNAVAILABLE else ContentEngineState.INCOMPLETE
        var contentEngineErrorCode: String? =
            if (nativeSession == null) "NATIVE_LIBRARY_UNAVAILABLE" else null
        var nativeMatches = emptySet<String>()

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
                    nativeMatches = nativeSession!!.finish()
                    contentEngineState = ContentEngineState.COMPLETE
                } catch (_: Exception) {
                    contentEngineState = ContentEngineState.INCOMPLETE
                    contentEngineErrorCode = "NATIVE_FINISH_FAILED"
                } catch (_: LinkageError) {
                    contentEngineState = ContentEngineState.INCOMPLETE
                    contentEngineErrorCode = "NATIVE_LINKAGE_FAILED"
                }
            }

            val hash = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
            val evidence = mutableListOf<ScanEvidence>()
            if (contentEngineState != ContentEngineState.COMPLETE) {
                evidence += ScanEvidence(
                    "NATIVE_CONTENT_ENGINE_INCOMPLETE",
                    "Native content analysis is unavailable or incomplete",
                    "The local C++ signature matcher did not complete. Its result is not used as evidence of a clean file.",
                    EvidenceSeverity.INFO
                )
            }
            if (contentBundle == null) {
                val state = ContentRuleBundleRuntime.state(context.applicationContext)
                evidence += ScanEvidence(
                    "SIGNED_CONTENT_RULES_${state.name}",
                    "Production content rules are not currently available",
                    when (state) {
                        ContentRuleBundleState.MISSING -> "No signed offline content-rule bundle is installed. Only built-in harmless self-tests are active."
                        ContentRuleBundleState.EXPIRED -> "The installed signed content-rule bundle has expired and is not used."
                        ContentRuleBundleState.INVALID -> "The installed content-rule bundle failed validation and is not used."
                        ContentRuleBundleState.CURRENT -> "A current bundle was reported, but could not be loaded for this scan."
                    },
                    EvidenceSeverity.INFO
                )
            }

            val selfTestMatch = NativeContentEngine.SELF_TEST_RULE_ID in nativeMatches
            val ruleById = contentBundle?.rules?.associateBy { it.id }.orEmpty()
            val matchedContentRules = nativeMatches.mapNotNull { ruleById[it] }
            matchedContentRules.forEach { rule ->
                evidence += ScanEvidence(
                    "CONTENT_SIGNATURE_${rule.id}",
                    "Content signature matched: ${rule.familyId}",
                    rule.description + " Confidence metadata: ${rule.confidence}%.",
                    when (rule.classification) {
                        ThreatClassification.MALWARE -> EvidenceSeverity.HIGH
                        ThreatClassification.PUA -> EvidenceSeverity.MEDIUM
                        ThreatClassification.SUSPICIOUS -> EvidenceSeverity.MEDIUM
                    }
                )
            }
            if (selfTestMatch) {
                evidence += ScanEvidence(
                    "NATIVE_ENGINE_SELF_TEST_MARKER",
                    "Harmless native-engine self-test marker matched",
                    "The C++ matcher recognized its dedicated harmless integration fixture. This is not a malware detection.",
                    EvidenceSeverity.INFO
                )
            }

            val localMatch = LocalIndicatorDatabase.lookup(hash)
            val eicarMatch = EicarTestDetector.contains(temp)
            val currentThreatFeed = ThreatFeedRuntime.currentFeed(context.applicationContext)
            val threatFeedStatus = ThreatFeedRuntime.status(context.applicationContext)
            val threatMatch = currentThreatFeed?.indicators?.get(hash.lowercase())
            if (threatMatch != null) {
                val label = when (threatMatch.classification) {
                    ThreatClassification.MALWARE -> "Known malware"
                    ThreatClassification.PUA -> "Potentially unwanted file"
                    ThreatClassification.SUSPICIOUS -> "Suspicious file"
                }
                evidence += ScanEvidence(
                    "SIGNED_FEED_${threatMatch.classification.name}",
                    label,
                    "Exact SHA-256 match in the authenticated feed. Family: ${threatMatch.familyId}. Sources: ${threatMatch.sources.sorted().joinToString()}.",
                    when (threatMatch.classification) {
                        ThreatClassification.MALWARE -> EvidenceSeverity.HIGH
                        ThreatClassification.PUA, ThreatClassification.SUSPICIOUS -> EvidenceSeverity.MEDIUM
                    }
                )
            }
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
                    if (stale) "The last authenticated threat feed has expired. A current feed no-match result is unavailable."
                    else "No valid current authenticated threat feed is available. A current feed no-match result is unavailable.",
                    EvidenceSeverity.INFO
                )
            }

            val looksLikeApk = ApkFileDetector.isApkArchive(temp) ||
                displayName.endsWith(".apk", ignoreCase = true) ||
                mimeType == "application/vnd.android.package-archive"
            val apk = if (looksLikeApk) ApkMetadataInspector.inspect(context, temp) else null
            val staticReport = FormatStaticAnalyzer.analyze(temp)
            val permissionAssessment = apk?.let(PermissionRiskAnalyzer::analyze)
            val combinedRisk = MultiSignalRiskScorer.assess(permissionAssessment, staticReport)
            evidence += combinedRisk.evidence

            if (!staticReport.complete) {
                evidence += ScanEvidence(
                    "STATIC_ANALYSIS_INCOMPLETE",
                    "Static format analysis was incomplete",
                    "One or more archive, DEX, or native-code limits were reached. No clean conclusion is drawn.",
                    EvidenceSeverity.INFO
                )
            }
            if (!staticReport.supported) {
                evidence += ScanEvidence(
                    "FORMAT_NOT_SUPPORTED",
                    "File format is not structurally covered",
                    "No configured APK/ZIP/ELF structural parser recognized this format.",
                    EvidenceSeverity.INFO
                )
            }

            val mlFeatures = OnDeviceMlScorer.extractFeatures(apk, staticReport, combinedRisk)
            val mlState = OnDeviceMlScorer.score(mlFeatures)
            val topContentRule = matchedContentRules.maxByOrNull {
                when (it.classification) {
                    ThreatClassification.MALWARE -> 3
                    ThreatClassification.PUA -> 2
                    ThreatClassification.SUSPICIOUS -> 1
                }
            }

            val verdict = when {
                threatMatch?.classification == ThreatClassification.MALWARE -> {
                    evidence += ScanEvidence(
                        "SIGNED_FEED_KNOWN_MALWARE", "Known malware hash match",
                        "Exact SHA-256 match in the current authenticated threat feed. Family: ${threatMatch.familyId}. This is a reputation match.",
                        EvidenceSeverity.HIGH
                    )
                    ScanVerdict.KNOWN_MALWARE
                }
                topContentRule?.classification == ThreatClassification.MALWARE -> ScanVerdict.KNOWN_MALWARE
                threatMatch?.classification == ThreatClassification.PUA ||
                    topContentRule?.classification == ThreatClassification.PUA -> ScanVerdict.POTENTIALLY_UNWANTED
                threatMatch?.classification == ThreatClassification.SUSPICIOUS ||
                    topContentRule?.classification == ThreatClassification.SUSPICIOUS -> ScanVerdict.SUSPICIOUS
                eicarMatch -> {
                    evidence += ScanEvidence(
                        "EICAR_TEST_FILE", "Harmless EICAR test string detected",
                        "The standard EICAR antivirus test string was detected. It is intentionally harmless and is used only to test scanner reporting.",
                        EvidenceSeverity.INFO
                    )
                    ScanVerdict.TEST_MARKER_MATCH
                }
                selfTestMatch -> ScanVerdict.TEST_MARKER_MATCH
                localMatch != null -> {
                    evidence += ScanEvidence(
                        "BENIGN_PROJECT_TEST_MARKER", "Benign project test marker matched",
                        "This is a harmless ANTIVIRUS AL AI test fixture. It is not malware.",
                        EvidenceSeverity.INFO
                    )
                    ScanVerdict.TEST_MARKER_MATCH
                }
                looksLikeApk && apk == null -> {
                    evidence += ScanEvidence(
                        "APK_PARSE_UNAVAILABLE", "APK metadata could not be parsed",
                        "The selected file looks like an APK, but Android's package parser could not read its metadata. The result is unknown, not clean.",
                        EvidenceSeverity.MEDIUM
                    )
                    ScanVerdict.UNKNOWN_APK
                }
                combinedRisk.suspicious -> ScanVerdict.SUSPICIOUS
                staticReport.supported || apk != null -> ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE
                else -> ScanVerdict.UNSUPPORTED_FILE
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
                contentRuleSetId = contentBundle?.let { "signed-content-rules-v${it.version}" }
                    ?: NativeContentEngine.RULE_SET_ID,
                contentRuleMatches = matchedContentRules.map { it.id },
                contentEngineErrorCode = contentEngineErrorCode,
                contentRuleBundleVersion = contentBundle?.version,
                staticAnalysis = StaticAnalysisSummary(
                    staticReport.format,
                    staticReport.supported,
                    staticReport.complete,
                    staticReport.entryCount,
                    staticReport.expandedBytes,
                    staticReport.signalCategories
                ),
                mlModelState = mlState,
                mlFeatureCount = mlFeatures.featureCount
            )
        } finally {
            runCatching { nativeSession?.close() }
            temp.delete()
        }
    }
}

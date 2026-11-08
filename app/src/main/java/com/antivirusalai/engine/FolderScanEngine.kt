package com.antivirusalai.engine

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

enum class FolderScanMode { ALL_FILES, APK_ONLY }

data class FolderScanItem(val uri: Uri, val result: ScanResult)

data class FolderScanFailure(val name: String, val reason: String)

data class FolderScanReport(
    val items: List<FolderScanItem>,
    val failures: List<FolderScanFailure>,
    val discoveredFiles: Int,
    val skippedFiles: Int,
    val truncated: Boolean,
    val scannedCountOverride: Int? = null,
    val suspiciousCountOverride: Int? = null,
    val unknownCountOverride: Int? = null,
    val matchedCountOverride: Int? = null
) {
    val scannedCount: Int get() = scannedCountOverride ?: items.size
    val suspiciousCount: Int get() = suspiciousCountOverride ?: items.count { it.result.verdict in setOf(ScanVerdict.KNOWN_MALWARE, ScanVerdict.POTENTIALLY_UNWANTED, ScanVerdict.SUSPICIOUS) }
    val unknownCount: Int get() = unknownCountOverride ?: items.count {
        it.result.verdict == ScanVerdict.UNKNOWN_APK ||
            it.result.verdict == ScanVerdict.UNSUPPORTED_FILE ||
            it.result.verdict == ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE
    }
    val matchedCount: Int get() = matchedCountOverride ?: items.count { it.result.verdict == ScanVerdict.TEST_MARKER_MATCH }

    /** Percentage of known file candidates that actually completed the scanner. */
    val scanCoveragePercent: Int get() =
        if (discoveredFiles == 0) {
            if (!truncated && failures.isEmpty()) 100 else 0
        } else ((scannedCount * 100L) / discoveredFiles).toInt().coerceIn(0, 100)

    /** Files with no scanned result and no explicit skip/failure disposition. */
    val unaccountedFiles: Int get() =
        (discoveredFiles - scannedCount - skippedFiles).coerceAtLeast(0)

    /** True only when every known candidate has a terminal scanned-or-skipped disposition. */
    val allDiscoveredFilesAccounted: Boolean get() = unaccountedFiles == 0

    /** True only when all known files were scanned and traversal did not report gaps. */
    val fullScanCoverage: Boolean get() =
        allDiscoveredFilesAccounted && skippedFiles == 0 && !truncated && failures.isEmpty()
}

/**
 * Scans files under one user-authorized SAF folder.
 * It never walks arbitrary device storage and never installs or executes files.
 */
object FolderScanEngine {
    const val MAX_FILES = ScanLimits.FOLDER_FILE_LIMIT
    const val MAX_DEPTH = 64
    const val MAX_TOTAL_BYTES = ScanLimits.FOLDER_TOTAL_BYTES
    private const val MAX_DIRECTORY_VISITS = ScanLimits.MAX_FOLDER_DIRECTORY_VISITS
    private const val MAX_PENDING_DIRECTORIES = ScanLimits.MAX_PENDING_DIRECTORIES

    private data class Candidate(
        val uri: Uri,
        val name: String,
        val declaredSize: Long
    )

    suspend fun scanFolder(
        context: Context,
        treeUri: Uri,
        mode: FolderScanMode,
        onProgress: suspend (current: Int, total: Int, name: String) -> Unit
    ): FolderScanReport = withContext(Dispatchers.IO) {
        val resolver = context.contentResolver
        val candidates = mutableListOf<Candidate>()
        val failures = mutableListOf<FolderScanFailure>()
        val visited = mutableSetOf<String>()
        val queue = ArrayDeque<Pair<String, Int>>()
        queue.add(DocumentsContract.getTreeDocumentId(treeUri) to 0)
        var truncated = false
        var discoverySkipped = 0
        var directoryVisits = 0

        while (queue.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            directoryVisits++
            if (directoryVisits > MAX_DIRECTORY_VISITS) {
                failures += FolderScanFailure(
                    "Folder traversal",
                    "Stopped after the 2,000-directory safety limit."
                )
                truncated = true
                break
            }
            val (directoryId, depth) = queue.removeFirst()
            if (depth > MAX_DEPTH) {
                failures += FolderScanFailure(directoryId, "Maximum folder depth reached.")
                truncated = true
                continue
            }
            if (!visited.add(directoryId)) continue

            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, directoryId)
            try {
                resolver.query(
                    childrenUri,
                    arrayOf(
                        DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                        DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                        DocumentsContract.Document.COLUMN_MIME_TYPE,
                        DocumentsContract.Document.COLUMN_SIZE
                    ),
                    null,
                    null,
                    null
                )?.use { cursor ->
                    val idColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                    val nameColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                    val mimeColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                    val sizeColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)

                    while (cursor.moveToNext()) {
                        val mime = if (mimeColumn >= 0) cursor.getString(mimeColumn) else null
                        val fallbackName = if (nameColumn >= 0) cursor.getString(nameColumn).orEmpty() else "Unnamed file"
                        if (idColumn < 0) {
                            // Without document IDs no SAF child URI can be constructed;
                            // this provider listing cannot be treated as complete.
                            truncated = true
                            if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                                failures += FolderScanFailure(fallbackName, "Directory identifier was unavailable; its contents could not be enumerated.")
                                truncated = true
                            } else {
                                discoverySkipped++
                                failures += FolderScanFailure(fallbackName, "Document identifier was unavailable; this file could not be opened for scanning.")
                            }
                            continue
                        }
                        val documentId = cursor.getString(idColumn)
                        if (documentId.isNullOrBlank()) {
                            if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                                failures += FolderScanFailure(fallbackName, "Directory identifier was empty; its contents could not be enumerated.")
                                truncated = true
                            } else {
                                discoverySkipped++
                                failures += FolderScanFailure(fallbackName, "Document identifier was empty; this file could not be opened for scanning.")
                            }
                            continue
                        }
                        val name = if (fallbackName.isNotBlank()) fallbackName else documentId
                        val size = if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) cursor.getLong(sizeColumn) else -1L

                        if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                            if (queue.size < MAX_PENDING_DIRECTORIES) {
                                queue.add(documentId to depth + 1)
                            } else {
                                failures += FolderScanFailure(
                                    name.ifBlank { documentId },
                                    "Directory queue reached the 30,000-entry safety limit."
                                )
                                truncated = true
                            }
                        } else {
                            val isApk = name.endsWith(".apk", ignoreCase = true) ||
                                mime == "application/vnd.android.package-archive"
                            if (mode == FolderScanMode.ALL_FILES || isApk) {
                                if (candidates.size >= MAX_FILES) {
                                    truncated = true
                                    break
                                }
                                candidates += Candidate(
                                    uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId),
                                    name = name.ifBlank { "Unnamed file" },
                                    declaredSize = size
                                )
                            }
                        }
                    }
                } ?: run {
                    failures.add(FolderScanFailure(directoryId, "Folder contents could not be listed."))
                    truncated = true
                }
            } catch (error: SecurityException) {
                failures += FolderScanFailure(directoryId, "Access denied by the document provider.")
                truncated = true
            } catch (error: Exception) {
                failures += FolderScanFailure(directoryId, error.message ?: "Folder could not be read.")
                truncated = true
            }
            if (truncated) break
        }

        // Count every result but keep only a bounded preview; retain detections first.
        val findingItems = mutableListOf<FolderScanItem>()
        val previewItems = mutableListOf<FolderScanItem>()
        var skipped = discoverySkipped
        var totalBytes = 0L
        var scannedCount = 0
        var suspiciousCount = 0
        var unknownCount = 0
        var matchedCount = 0
        for ((index, candidate) in candidates.withIndex()) {
            currentCoroutineContext().ensureActive()
            if (candidate.declaredSize > ScanEngine.MAX_FILE_SIZE_BYTES) {
                skipped++
                failures += FolderScanFailure(candidate.name, "File exceeds the 200 MB per-file limit.")
                continue
            }
            if (candidate.declaredSize > 0L &&
                totalBytes + candidate.declaredSize > MAX_TOTAL_BYTES
            ) {
                skipped++
                failures += FolderScanFailure(candidate.name, "Folder scan reached the 25 GB total data limit.")
                truncated = true
                continue
            }

            withContext(Dispatchers.Main.immediate) {
                onProgress(index + 1, candidates.size, candidate.name)
            }
            try {
                val result = ScanEngine.scan(context.applicationContext, candidate.uri)
                totalBytes += result.sizeBytes
                scannedCount++
                when (result.verdict) {
                    ScanVerdict.KNOWN_MALWARE,
                    ScanVerdict.POTENTIALLY_UNWANTED,
                    ScanVerdict.SUSPICIOUS -> suspiciousCount++
                    ScanVerdict.UNKNOWN_APK,
                    ScanVerdict.UNSUPPORTED_FILE,
                    ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE -> unknownCount++
                    ScanVerdict.TEST_MARKER_MATCH -> matchedCount++
                    ScanVerdict.NO_KNOWN_INDICATOR -> Unit
                }
                val reportItem = FolderScanItem(candidate.uri, result)
                val isPriorityFinding = result.verdict in setOf(
                    ScanVerdict.KNOWN_MALWARE,
                    ScanVerdict.POTENTIALLY_UNWANTED,
                    ScanVerdict.SUSPICIOUS
                )
                if (isPriorityFinding) {
                    if (findingItems.size < ScanLimits.MAX_RESULT_DETAILS) findingItems += reportItem
                } else if (previewItems.size < ScanLimits.MAX_RESULT_DETAILS) {
                    previewItems += reportItem
                }
                if (totalBytes >= MAX_TOTAL_BYTES) {
                    truncated = index < candidates.lastIndex
                    if (truncated) {
                        skipped += candidates.size - index - 1
                        failures += FolderScanFailure(
                            "Remaining files",
                            "Stopped after reaching the 25 GB total data limit."
                        )
                    }
                    break
                }
            } catch (error: kotlinx.coroutines.CancellationException) {
                throw error
            } catch (error: Exception) {
                skipped++
                failures += FolderScanFailure(candidate.name, error.message ?: "File scan failed.")
            }
        }

        FolderScanReport(
            items = if (findingItems.isNotEmpty()) findingItems else previewItems,
            failures = failures,
            discoveredFiles = candidates.size + discoverySkipped,
            skippedFiles = skipped,
            truncated = truncated || skipped > 0,
            scannedCountOverride = scannedCount,
            suspiciousCountOverride = suspiciousCount,
            unknownCountOverride = unknownCount,
            matchedCountOverride = matchedCount
        )
    }
}

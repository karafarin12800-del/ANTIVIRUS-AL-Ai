package com.antivirusalai.engine

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Device-wide shared-storage scanner.
 *
 * Android still protects other apps' private data and parts of /Android.
 * On Android 11+, broad shared-storage traversal requires the user to grant
 * MANAGE_EXTERNAL_STORAGE in system settings.
 */
object DeviceScanEngine {
    private const val QUICK_FILE_LIMIT = 350
    private const val QUICK_TOTAL_BYTES = 1024L * 1024L * 1024L
    private const val MAX_DEPTH = 64
    private val QUICK_DIRECTORIES = listOf(
        "Download", "Downloads", "Documents", "Bluetooth", "DCIM",
        "Pictures", "Movies", "Music", "Podcasts", "Notifications",
        "Ringtones", "Recordings", "Android/media"
    )

    fun hasBroadStorageAccess(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.R || Environment.isExternalStorageManager()

    suspend fun scanDevice(
        context: Context,
        deep: Boolean,
        onProgress: suspend (current: Int, total: Int, name: String) -> Unit
    ): FolderScanReport = withContext(Dispatchers.IO) {
        require(hasBroadStorageAccess()) {
            "برای اسکن خودکار حافظه، دسترسی «مدیریت همه فایل‌ها» باید در تنظیمات Android فعال شود."
        }

        val roots = findStorageRoots(context)
        val failures = mutableListOf<FolderScanFailure>()
        val candidates = linkedMapOf<String, File>()
        val maxFiles = if (deep) Int.MAX_VALUE else QUICK_FILE_LIMIT

        fun addCandidate(file: File) {
            if (candidates.size >= maxFiles || !file.isFile || !file.canRead()) return
            val canonical = runCatching { file.canonicalFile }.getOrNull() ?: return
            if (candidates.putIfAbsent(canonical.path, canonical) == null) Unit
        }

        if (deep) {
            roots.forEach { root ->
                val rootCanonical = runCatching { root.canonicalFile }.getOrNull() ?: return@forEach
                val queue = ArrayDeque<Pair<File, Int>>()
                queue.add(rootCanonical to 0)
                val visited = mutableSetOf<String>()
                while (queue.isNotEmpty() && candidates.size < maxFiles) {
                    currentCoroutineContext().ensureActive()
                    val (directory, depth) = queue.removeFirst()
                    if (depth > MAX_DEPTH) {
                        failures += FolderScanFailure(directory.name, "Maximum directory depth reached.")
                        continue
                    }
                    val canonical = runCatching { directory.canonicalFile }.getOrNull() ?: continue
                    if (!canonical.path.startsWith(rootCanonical.path + File.separator) &&
                        canonical.path != rootCanonical.path
                    ) continue
                    if (!visited.add(canonical.path)) continue
                    if (isProtectedDirectory(rootCanonical, canonical)) continue
                    val children = try {
                        canonical.listFiles()
                    } catch (_: SecurityException) {
                        failures += FolderScanFailure(canonical.name, "Access denied by Android.")
                        null
                    }
                    if (children == null) continue
                    children.forEach { child ->
                        if (candidates.size >= maxFiles) return@forEach
                        if (child.isDirectory) {
                            if (!isProtectedDirectory(rootCanonical, child)) {
                                queue.add(child to depth + 1)
                            }
                        } else {
                            addCandidate(child)
                        }
                    }
                }
            }
            addInstalledApplicationPackages(context, candidates, failures, maxFiles)
        } else {
            // Include loose files placed directly in shared-storage roots. Some devices
            // and users do not keep downloads inside the standard named folders.
            for (root in roots) {
                if (candidates.size >= maxFiles) break
                runCatching { root.listFiles() }.getOrNull()
                    ?.filter { it.isFile }
                    ?.forEach { file ->
                        if (candidates.size < maxFiles) addCandidate(file)
                    }
            }

            for (root in roots) {
                if (candidates.size >= maxFiles) break
                for (relative in QUICK_DIRECTORIES) {
                    if (candidates.size >= maxFiles) break
                    val directory = File(root, relative)
                    if (directory.isDirectory) {
                        collectQuickFiles(directory, candidates, failures, maxFiles)
                    }
                }
            }

            // Installed application packages are a high-value quick-scan target,
            // not something users should have to wait for a deep scan to inspect.
            addInstalledApplicationPackages(context, candidates, failures, maxFiles)
        }

        val items = mutableListOf<FolderScanItem>()
        var skipped = 0
        var totalBytes = 0L
        var scannedCount = 0
        var suspiciousCount = 0
        var unknownCount = 0
        var matchedCount = 0
        val list = candidates.values.toList()
        for ((index, file) in list.withIndex()) {
            currentCoroutineContext().ensureActive()
            val declaredSize = file.length()
            if (declaredSize > ScanEngine.MAX_FILE_SIZE_BYTES) {
                skipped++
                failures += FolderScanFailure(file.name, "File exceeds the 200 MB per-file limit.")
                continue
            }
            if (!deep && declaredSize > 0 && totalBytes + declaredSize > QUICK_TOTAL_BYTES) {
                skipped++
                failures += FolderScanFailure(file.name, "The 1 GB quick-scan data limit was reached.")
                continue
            }
            if (index == 0 || index % 5 == 0 || index == list.lastIndex) {
                withContext(Dispatchers.Main.immediate) {
                    onProgress(index + 1, list.size, file.name)
                }
            }
            try {
                val result = ScanEngine.scan(context.applicationContext, Uri.fromFile(file))
                totalBytes += result.sizeBytes
                scannedCount++
                when (result.verdict) {
                    ScanVerdict.KNOWN_MALWARE, ScanVerdict.POTENTIALLY_UNWANTED, ScanVerdict.SUSPICIOUS -> suspiciousCount++
                    ScanVerdict.UNKNOWN_APK, ScanVerdict.UNSUPPORTED_FILE -> unknownCount++
                    ScanVerdict.TEST_MARKER_MATCH -> matchedCount++
                    ScanVerdict.NO_KNOWN_INDICATOR -> Unit
                }
                if (items.size < 60) items += FolderScanItem(Uri.fromFile(file), result)
                if (!deep && totalBytes >= QUICK_TOTAL_BYTES) {
                    skipped += list.size - index - 1
                    failures += FolderScanFailure("Remaining files", "Stopped at the 1 GB quick-scan data limit.")
                    break
                }
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                failures += FolderScanFailure(file.name, error.message ?: "File scan failed.")
            }
        }

        val truncated = !deep && candidates.size >= maxFiles
        if (truncated) {
            failures += FolderScanFailure(
                "Scan limit",
                "The 350-file quick-scan limit was reached."
            )
        }
        FolderScanReport(
            items = items,
            failures = failures,
            discoveredFiles = list.size,
            skippedFiles = skipped,
            truncated = truncated,
            scannedCountOverride = scannedCount,
            suspiciousCountOverride = suspiciousCount,
            unknownCountOverride = unknownCount,
            matchedCountOverride = matchedCount
        )
    }

    private fun findStorageRoots(context: Context): List<File> {
        val roots = linkedMapOf<String, File>()
        val candidates = mutableListOf<File>()
        candidates += Environment.getExternalStorageDirectory()
        context.getExternalFilesDirs(null).filterNotNull().forEach { appFiles ->
            val path = appFiles.absolutePath
            val marker = path.indexOf("/Android/data/")
            if (marker > 0) candidates += File(path.substring(0, marker))
        }
        candidates.forEach { candidate ->
            val root = runCatching { candidate.canonicalFile }.getOrNull() ?: return@forEach
            if (root.isDirectory && root.canRead()) roots[root.path] = root
        }
        return roots.values.toList()
    }

    private fun isProtectedDirectory(root: File, directory: File): Boolean {
        val relative = runCatching {
            directory.canonicalPath.removePrefix(root.canonicalPath).trimStart(File.separatorChar)
        }.getOrDefault("")
        val parts = relative.split(File.separatorChar)
        return parts.size >= 2 && parts[0].equals("Android", true) &&
            (parts[1].equals("data", true) || parts[1].equals("obb", true))
    }

    private suspend fun collectQuickFiles(
        start: File,
        output: LinkedHashMap<String, File>,
        failures: MutableList<FolderScanFailure>,
        maxFiles: Int
    ) {
        val queue = ArrayDeque<Pair<File, Int>>()
        queue.add(start to 0)
        while (queue.isNotEmpty() && output.size < maxFiles) {
            currentCoroutineContext().ensureActive()
            val (directory, depth) = queue.removeFirst()
            if (depth > 12) continue
            val children = try {
                directory.listFiles()
            } catch (_: SecurityException) {
                failures += FolderScanFailure(directory.name, "Access denied by Android.")
                null
            } ?: continue
            children.forEach { child ->
                if (output.size >= maxFiles) return@forEach
                if (child.isDirectory) queue.add(child to depth + 1)
                else if (child.isFile && child.canRead()) {
                    val canonical = runCatching { child.canonicalFile }.getOrNull() ?: return@forEach
                    output.putIfAbsent(canonical.path, canonical)
                }
            }
        }
    }

    private fun addInstalledApplicationPackages(
        context: Context,
        output: LinkedHashMap<String, File>,
        failures: MutableList<FolderScanFailure>,
        maxFiles: Int
    ) {
        val pm = context.packageManager
        val apps = try {
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledApplications(0)
            }
        } catch (error: Exception) {
            failures += FolderScanFailure("Installed apps", error.message ?: "App inventory unavailable.")
            return
        }
        apps.forEach { app ->
            if (output.size >= maxFiles) return@forEach
            addPackageArchive(app.sourceDir, output, maxFiles)
            app.splitSourceDirs.orEmpty().forEach { addPackageArchive(it, output, maxFiles) }
        }
    }

    private fun addPackageArchive(
        path: String?,
        output: LinkedHashMap<String, File>,
        maxFiles: Int
    ) {
        if (output.size >= maxFiles || path.isNullOrBlank()) return
        val file = File(path)
        if (!file.isFile || !file.canRead()) return
        val canonical = runCatching { file.canonicalFile }.getOrNull() ?: return
        output.putIfAbsent(canonical.path, canonical)
    }
}

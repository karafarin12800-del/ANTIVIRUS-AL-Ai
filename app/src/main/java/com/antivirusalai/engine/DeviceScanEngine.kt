package com.antivirusalai.engine

import android.content.Context
import android.content.pm.ApplicationInfo
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
    private const val DEEP_FILE_LIMIT = 2500
    private const val MAX_TOTAL_BYTES = 2L * 1024L * 1024L * 1024L
    private const val MAX_DEPTH = 32
    private val QUICK_DIRECTORIES = listOf(
        "Download", "Documents", "Bluetooth", "DCIM",
        "Pictures", "Movies", "Music", "Android/media"
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
        val maxFiles = if (deep) DEEP_FILE_LIMIT else QUICK_FILE_LIMIT

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
            roots.forEach { root ->
                QUICK_DIRECTORIES.forEach { relative ->
                    if (candidates.size >= maxFiles) return@forEach
                    val directory = File(root, relative)
                    if (directory.isDirectory) {
                        collectQuickFiles(directory, candidates, failures, maxFiles)
                    }
                }
            }
        }

        val items = mutableListOf<FolderScanItem>()
        var skipped = 0
        var totalBytes = 0L
        val list = candidates.values.toList()
        for ((index, file) in list.withIndex()) {
            currentCoroutineContext().ensureActive()
            val declaredSize = file.length()
            if (declaredSize > ScanEngine.MAX_FILE_SIZE_BYTES) {
                skipped++
                failures += FolderScanFailure(file.name, "File exceeds the 200 MB per-file limit.")
                continue
            }
            if (declaredSize > 0 && totalBytes + declaredSize > MAX_TOTAL_BYTES) {
                skipped++
                failures += FolderScanFailure(file.name, "The 2 GB scan data limit was reached.")
                continue
            }
            onProgress(index + 1, list.size, file.name)
            try {
                val result = ScanEngine.scan(context.applicationContext, Uri.fromFile(file))
                totalBytes += result.sizeBytes
                items += FolderScanItem(Uri.fromFile(file), result)
                if (totalBytes >= MAX_TOTAL_BYTES) {
                    skipped += list.size - index - 1
                    failures += FolderScanFailure("Remaining files", "Stopped at the 2 GB data limit.")
                    break
                }
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                failures += FolderScanFailure(file.name, error.message ?: "File scan failed.")
            }
        }

        val truncated = candidates.size >= maxFiles
        if (truncated) {
            failures += FolderScanFailure(
                "Scan limit",
                if (deep) "The 2,500-file deep-scan limit was reached."
                else "The 350-file quick-scan limit was reached."
            )
        }
        FolderScanReport(
            items = items,
            failures = failures,
            discoveredFiles = list.size,
            skippedFiles = skipped,
            truncated = truncated
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
            addPackageArchive(app.sourceDir, output)
            app.splitSourceDirs.orEmpty().forEach { addPackageArchive(it, output) }
        }
    }

    private fun addPackageArchive(
        path: String?,
        output: LinkedHashMap<String, File>
    ) {
        if (path.isNullOrBlank()) return
        val file = File(path)
        if (!file.isFile || !file.canRead()) return
        val canonical = runCatching { file.canonicalFile }.getOrNull() ?: return
        output.putIfAbsent(canonical.path, canonical)
    }
}

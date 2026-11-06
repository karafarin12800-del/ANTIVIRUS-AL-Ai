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
    private const val DEEP_FILE_LIMIT = 10_000
    private const val DEEP_TOTAL_BYTES = 5L * 1024L * 1024L * 1024L
    private const val MAX_DEPTH = 64
    private const val MAX_DIRECTORY_VISITS = 20_000
    private const val MAX_QUICK_DIRECTORY_VISITS = 3_000
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
        val maxFiles = if (deep) DEEP_FILE_LIMIT else QUICK_FILE_LIMIT
        var traversalLimitReached = false
        var dataLimitReached = false
        var discoverySkipped = 0

        fun addCandidate(file: File, allowedRoot: File) {
            if (candidates.size >= maxFiles || !file.isFile) return
            if (!file.canRead()) {
                discoverySkipped++
                failures += FolderScanFailure(file.name, "File is not readable by this app.")
                return
            }
            val canonical = try {
                file.canonicalFile
            } catch (error: Exception) {
                discoverySkipped++
                traversalLimitReached = true
                failures += FolderScanFailure(file.name, "Could not resolve the file's canonical path.")
                return
            }
            val rootPath = allowedRoot.canonicalPath
            if (canonical.path != rootPath &&
                !canonical.path.startsWith(rootPath + File.separator)
            ) {
                discoverySkipped++
                traversalLimitReached = true
                failures += FolderScanFailure(file.name, "A file path outside the selected storage root was skipped.")
                return
            }
            candidates.putIfAbsent(canonical.path, canonical)
        }

        if (deep) {
            roots.forEach { root ->
                val rootCanonical = runCatching { root.canonicalFile }.getOrNull() ?: return@forEach
                val queue = ArrayDeque<Pair<File, Int>>()
                queue.add(rootCanonical to 0)
                val visited = mutableSetOf<String>()
                var directoryVisits = 0
                while (queue.isNotEmpty() && candidates.size < maxFiles) {
                    currentCoroutineContext().ensureActive()
                    directoryVisits++
                    if (directoryVisits > MAX_DIRECTORY_VISITS) {
                        failures += FolderScanFailure(
                            rootCanonical.name,
                            "Deep scan stopped after the 20,000-directory safety limit."
                        )
                        traversalLimitReached = true
                        break
                    }
                    val (directory, depth) = queue.removeFirst()
                    if (depth > MAX_DEPTH) {
                        failures += FolderScanFailure(directory.name, "Maximum directory depth reached.")
                        traversalLimitReached = true
                        continue
                    }
                    val canonical = try {
                        directory.canonicalFile
                    } catch (_: Exception) {
                        failures += FolderScanFailure(directory.name, "Could not resolve directory path.")
                        traversalLimitReached = true
                        continue
                    }
                    if (!canonical.path.startsWith(rootCanonical.path + File.separator) &&
                        canonical.path != rootCanonical.path
                    ) {
                        failures += FolderScanFailure(directory.name, "A path outside the selected storage root was skipped.")
                        traversalLimitReached = true
                        continue
                    }
                    if (!visited.add(canonical.path)) continue
                    if (isProtectedDirectory(rootCanonical, canonical)) continue
                    var listingFailure: String? = null
                    val children = try {
                        canonical.listFiles()
                    } catch (_: SecurityException) {
                        listingFailure = "Access denied by Android."
                        null
                    }
                    if (children == null) {
                        failures += FolderScanFailure(
                            canonical.name,
                            listingFailure ?: "Android did not return a directory listing."
                        )
                        traversalLimitReached = true
                        continue
                    }
                    children.forEach { child ->
                        if (candidates.size >= maxFiles) return@forEach
                        if (child.isDirectory) {
                            if (!isProtectedDirectory(rootCanonical, child)) {
                                queue.add(child to depth + 1)
                            }
                        } else {
                            addCandidate(child, rootCanonical)
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
                val rootChildren = try {
                    root.listFiles()
                } catch (_: SecurityException) {
                    failures += FolderScanFailure(root.name, "Access to the storage root was denied.")
                    null
                }
                if (rootChildren == null) {
                    failures += FolderScanFailure(root.name, "The storage root could not be listed.")
                    traversalLimitReached = true
                } else {
                    rootChildren.filter { it.isFile }.forEach { file ->
                        if (candidates.size < maxFiles) addCandidate(file, root)
                    }
                }
            }

            for (root in roots) {
                if (candidates.size >= maxFiles) break
                for (relative in QUICK_DIRECTORIES) {
                    if (candidates.size >= maxFiles) break
                    val directory = File(root, relative)
                    if (directory.isDirectory) {
                        if (collectQuickFiles(directory, root, candidates, failures, maxFiles)) {
                            traversalLimitReached = true
                        }
                    }
                }
            }

            // Installed application packages are a high-value quick-scan target,
            // not something users should have to wait for a deep scan to inspect.
            addInstalledApplicationPackages(context, candidates, failures, maxFiles)
        }

        val items = mutableListOf<FolderScanItem>()
        var skipped = discoverySkipped
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
            val totalByteLimit = if (deep) DEEP_TOTAL_BYTES else QUICK_TOTAL_BYTES
            if (declaredSize > 0 && declaredSize > totalByteLimit - totalBytes) {
                dataLimitReached = true
                skipped++
                failures += FolderScanFailure(
                    file.name,
                    if (deep) "The 5 GB deep-scan data limit was reached."
                    else "The 1 GB quick-scan data limit was reached."
                )
                if (totalBytes >= totalByteLimit) {
                    skipped += list.size - index - 1
                    break
                }
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
                if (totalBytes >= totalByteLimit && index < list.lastIndex) {
                    skipped += list.size - index - 1
                    failures += FolderScanFailure(
                        "Remaining files",
                        if (deep) "Stopped at the 5 GB deep-scan data limit."
                        else "Stopped at the 1 GB quick-scan data limit."
                    )
                    break
                }
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                skipped++
                failures += FolderScanFailure(file.name, error.message ?: "File scan failed.")
            }
        }

        val truncated = traversalLimitReached || dataLimitReached || candidates.size >= maxFiles || skipped > 0
        if (candidates.size >= maxFiles) {
            failures += FolderScanFailure(
                "Scan limit",
                if (deep) "The 10,000-file deep-scan limit was reached."
                else "The 350-file quick-scan limit was reached."
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
        root: File,
        output: LinkedHashMap<String, File>,
        failures: MutableList<FolderScanFailure>,
        maxFiles: Int
    ): Boolean {
        val queue = ArrayDeque<Pair<File, Int>>()
        queue.add(start to 0)
        val visited = mutableSetOf<String>()
        var directoryVisits = 0
        var limitReached = false
        while (queue.isNotEmpty() && output.size < maxFiles) {
            currentCoroutineContext().ensureActive()
            directoryVisits++
            if (directoryVisits > MAX_QUICK_DIRECTORY_VISITS) {
                failures += FolderScanFailure(
                    start.name,
                    "Quick scan stopped after the 3,000-directory safety limit."
                )
                return true
            }
            val (directory, depth) = queue.removeFirst()
            if (depth > 12) {
                failures += FolderScanFailure(directory.name, "Quick scan maximum depth reached.")
                limitReached = true
                continue
            }
            val canonicalDirectory = try {
                directory.canonicalFile
            } catch (_: Exception) {
                failures += FolderScanFailure(directory.name, "Could not resolve directory path.")
                limitReached = true
                continue
            }
            val rootPath = root.canonicalPath
            if (canonicalDirectory.path != rootPath &&
                !canonicalDirectory.path.startsWith(rootPath + File.separator)
            ) {
                failures += FolderScanFailure(directory.name, "A path outside the selected storage root was skipped.")
                limitReached = true
                continue
            }
            if (isProtectedDirectory(root, canonicalDirectory)) continue
            if (!visited.add(canonicalDirectory.path)) continue
            var listingFailure: String? = null
            val children = try {
                canonicalDirectory.listFiles()
            } catch (_: SecurityException) {
                listingFailure = "Access denied by Android."
                null
            }
            if (children == null) {
                failures += FolderScanFailure(
                    canonicalDirectory.name,
                    listingFailure ?: "Android did not return a directory listing."
                )
                limitReached = true
                continue
            }
            children.forEach { child ->
                if (output.size >= maxFiles) return@forEach
                if (child.isDirectory) {
                    queue.add(child to depth + 1)
                } else if (child.isFile) {
                    if (!child.canRead()) {
                        failures += FolderScanFailure(child.name, "File is not readable by this app.")
                        limitReached = true
                        return@forEach
                    }
                    val canonical = try {
                        child.canonicalFile
                    } catch (_: Exception) {
                        failures += FolderScanFailure(child.name, "Could not resolve file path.")
                        limitReached = true
                        return@forEach
                    }
                    if (canonical.path != rootPath && !canonical.path.startsWith(rootPath + File.separator)) {
                        failures += FolderScanFailure(child.name, "A file path outside the selected storage root was skipped.")
                        limitReached = true
                    } else {
                        output.putIfAbsent(canonical.path, canonical)
                    }
                }
            }
        }
        return limitReached
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

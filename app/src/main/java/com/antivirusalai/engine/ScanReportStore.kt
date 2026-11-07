package com.antivirusalai.engine

import android.content.Context
import android.net.Uri
import org.json.JSONArray
import org.json.JSONObject

data class StoredDeviceScan(val deep: Boolean, val report: FolderScanReport)

object ScanReportStore {
    private const val PREFS = "device-scan-report"
    private const val REPORT_KEY = "latest_report"

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(REPORT_KEY).apply()
    }

    fun save(context: Context, deep: Boolean, report: FolderScanReport) {
        val root = JSONObject()
            .put("deep", deep)
            .put("discoveredFiles", report.discoveredFiles)
            .put("skippedFiles", report.skippedFiles)
            .put("truncated", report.truncated)
            .put("scannedCountOverride", report.scannedCountOverride ?: JSONObject.NULL)
            .put("suspiciousCountOverride", report.suspiciousCountOverride ?: JSONObject.NULL)
            .put("unknownCountOverride", report.unknownCountOverride ?: JSONObject.NULL)
            .put("matchedCountOverride", report.matchedCountOverride ?: JSONObject.NULL)
        val items = JSONArray()
        report.items.take(60).forEach { item ->
            items.put(JSONObject().put("uri", item.uri.toString()).put("result", encodeResult(item.result)))
        }
        val failures = JSONArray()
        report.failures.take(100).forEach { failure ->
            failures.put(JSONObject().put("name", failure.name).put("reason", failure.reason))
        }
        root.put("items", items).put("failures", failures)
        check(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(REPORT_KEY, root.toString()).commit()) { "The scan report could not be saved." }
    }

    fun load(context: Context): StoredDeviceScan? = runCatching {
        val encoded = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(REPORT_KEY, null) ?: return null
        val root = JSONObject(encoded)
        val items = mutableListOf<FolderScanItem>()
        val itemArray = root.optJSONArray("items") ?: JSONArray()
        for (index in 0 until itemArray.length()) {
            val item = itemArray.optJSONObject(index) ?: continue
            val uri = item.optString("uri").takeIf { it.isNotBlank() } ?: continue
            val resultObject = item.optJSONObject("result") ?: continue
            val result = decodeResult(resultObject) ?: continue
            items += FolderScanItem(Uri.parse(uri), result)
        }
        val failures = mutableListOf<FolderScanFailure>()
        val failureArray = root.optJSONArray("failures") ?: JSONArray()
        for (index in 0 until failureArray.length()) {
            val item = failureArray.optJSONObject(index) ?: continue
            failures += FolderScanFailure(item.optString("name"), item.optString("reason"))
        }
        StoredDeviceScan(
            deep = root.optBoolean("deep", false),
            report = FolderScanReport(
                items = items, failures = failures,
                discoveredFiles = root.optInt("discoveredFiles"),
                skippedFiles = root.optInt("skippedFiles"),
                truncated = root.optBoolean("truncated"),
                scannedCountOverride = root.nullableInt("scannedCountOverride"),
                suspiciousCountOverride = root.nullableInt("suspiciousCountOverride"),
                unknownCountOverride = root.nullableInt("unknownCountOverride"),
                matchedCountOverride = root.nullableInt("matchedCountOverride")
            )
        )
    }.getOrNull()

    private fun encodeResult(result: ScanResult): JSONObject {
        val evidence = JSONArray()
        result.evidence.forEach { item ->
            evidence.put(JSONObject().put("code", item.code).put("title", item.title)
                .put("detail", item.detail).put("severity", item.severity.name))
        }
        val apk = result.apkMetadata?.let { metadata ->
            val permissions = JSONArray()
            metadata.requestedPermissions.sorted().forEach { permissions.put(it) }
            JSONObject().put("packageName", metadata.packageName)
                .put("versionName", metadata.versionName ?: JSONObject.NULL)
                .put("targetSdk", metadata.targetSdk)
                .put("requestedPermissions", permissions)
                .put("debuggable", metadata.debuggable)
                .put("signingCertificateSha256", metadata.signingCertificateSha256 ?: JSONObject.NULL)
                .put("exportedComponentCount", metadata.exportedComponentCount)
                .put("declaredAccessibilityServiceCount", metadata.declaredAccessibilityServiceCount)
        }
        return JSONObject().put("displayName", result.displayName)
            .put("mimeType", result.mimeType ?: JSONObject.NULL)
            .put("sizeBytes", result.sizeBytes).put("sha256", result.sha256)
            .put("verdict", result.verdict.name).put("evidence", evidence)
            .put("apkMetadata", apk ?: JSONObject.NULL).put("durationMillis", result.durationMillis)
    }

    private fun decodeResult(value: JSONObject): ScanResult? = runCatching {
        val verdict = runCatching { ScanVerdict.valueOf(value.getString("verdict")) }
            .getOrDefault(ScanVerdict.UNSUPPORTED_FILE)
        val evidence = mutableListOf<ScanEvidence>()
        val evidenceArray = value.optJSONArray("evidence") ?: JSONArray()
        for (index in 0 until evidenceArray.length()) {
            val item = evidenceArray.optJSONObject(index) ?: continue
            val severity = runCatching { EvidenceSeverity.valueOf(item.getString("severity")) }
                .getOrDefault(EvidenceSeverity.INFO)
            evidence += ScanEvidence(item.optString("code"), item.optString("title"),
                item.optString("detail"), severity)
        }
        val apkValue = value.opt("apkMetadata")
        val apk = if (apkValue is JSONObject) {
            val permissions = apkValue.optJSONArray("requestedPermissions") ?: JSONArray()
            val permissionSet = buildSet {
                for (index in 0 until permissions.length()) {
                    permissions.optString(index).takeIf { it.isNotBlank() }?.let { add(it) }
                }
            }
            ApkMetadata(
                packageName = apkValue.optString("packageName"),
                versionName = apkValue.nullableString("versionName"),
                targetSdk = apkValue.optInt("targetSdk"),
                requestedPermissions = permissionSet,
                debuggable = apkValue.optBoolean("debuggable"),
                signingCertificateSha256 = apkValue.nullableString("signingCertificateSha256"),
                exportedComponentCount = apkValue.optInt("exportedComponentCount"),
                declaredAccessibilityServiceCount = apkValue.optInt("declaredAccessibilityServiceCount")
            )
        } else null
        ScanResult(
            displayName = value.optString("displayName"), mimeType = value.nullableString("mimeType"),
            sizeBytes = value.optLong("sizeBytes"), sha256 = value.optString("sha256"),
            verdict = verdict, evidence = evidence, apkMetadata = apk,
            durationMillis = value.optLong("durationMillis")
        )
    }.getOrNull()

    private fun JSONObject.nullableString(key: String): String? {
        val value = opt(key)
        return if (value == null || value == JSONObject.NULL) null else value as? String
    }
    private fun JSONObject.nullableInt(key: String): Int? {
        val value = opt(key)
        return if (value == null || value == JSONObject.NULL) null else (value as? Number)?.toInt()
    }
}

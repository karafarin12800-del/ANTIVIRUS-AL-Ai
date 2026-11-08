package com.antivirusalai.intel

import android.content.Context
import com.antivirusalai.engine.ContentSignatureRule
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.URL
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.Signature
import java.util.Base64
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class SignedContentRuleBundle(
    val keyId: String,
    val version: Long,
    val issuedAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val rules: List<ContentSignatureRule>
)

enum class ContentRuleBundleState { CURRENT, MISSING, EXPIRED, INVALID }

object ContentRuleBundleParser {
    const val HEADER = "ALAI-CONTENT-RULES/2"
    const val MAX_BUNDLE_BYTES = 1024 * 1024
    const val MAX_RULES = 511
    const val MAX_PATTERN_BYTES = 256
    const val MAX_TOTAL_PATTERN_BYTES = 64 * 1024 - 30 // reserve space for the built-in self-test pattern
    const val MAX_VALIDITY_SECONDS = 14L * 24L * 60L * 60L
    private const val KEY_ID = "alai-release-2026"
    private const val PUBLIC_KEY_B64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM1szM5WLCBP0KDTXsrVfBdPxErB4sVo4mhY+duhjfDP5MwASTx0pLor3mSL7dLRwX/gZpi6odLquz/BfIGSafg=="
    private val idPattern = Regex("[A-Za-z0-9._-]{1,64}")
    private val familyPattern = Regex("[A-Z0-9][A-Z0-9._-]{0,79}")
    private val sourcePattern = Regex("[A-Z0-9][A-Z0-9._-]{0,79}")
    private val licensePattern = Regex("[A-Za-z0-9.+-]{1,64}")
    private val longPattern = Regex("[1-9][0-9]{0,18}")

    fun parse(
        bytes: ByteArray,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000L,
        minimumVersionExclusive: Long = 0L
    ): SignedContentRuleBundle {
        require(bytes.isNotEmpty() && bytes.size <= MAX_BUNDLE_BYTES) { "Rule bundle is empty or too large." }
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (error: CharacterCodingException) {
            throw IllegalArgumentException("Rule bundle is not valid UTF-8.", error)
        }
        require(!text.contains('\r') && text.endsWith('\n')) { "Rule bundle must use LF and end with a newline." }
        val lines = text.dropLast(1).split('\n')
        require(lines.size >= 6 && lines.first() == HEADER) { "Unsupported content-rule bundle format." }
        val signatureLine = lines.last()
        require(signatureLine.startsWith("signature=")) { "Missing final signature." }
        val signatureBytes = Base64.getDecoder().decode(signatureLine.removePrefix("signature="))
        val payload = lines.dropLast(1).joinToString("\n", postfix = "\n").toByteArray(StandardCharsets.UTF_8)
        val keyId = lines[1].removePrefix("key_id=").takeIf { lines[1].startsWith("key_id=") }
            ?: throw IllegalArgumentException("Missing key ID.")
        require(keyId == KEY_ID) { "Untrusted rule-bundle key ID." }
        val version = parsePositive(lines[2], "version=")
        val issued = parsePositive(lines[3], "issued_at=")
        val expires = parsePositive(lines[4], "expires_at=")
        require(version > minimumVersionExclusive) { "Rule bundle rollback detected." }
        require(issued <= nowEpochSeconds + 300L) { "Rule bundle issue time is in the future." }
        require(expires > nowEpochSeconds && expires > issued) { "Rule bundle is expired or has invalid dates." }
        require(expires - issued <= MAX_VALIDITY_SECONDS) { "Rule bundle validity exceeds policy." }

        val publicKey = EcdsaP256KeyringVerifier.decodeX509PublicKey(PUBLIC_KEY_B64)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(payload)
        val valid = try {
            verifier.verify(signatureBytes)
        } catch (error: Exception) {
            throw IllegalArgumentException("Rule bundle signature encoding is invalid.", error)
        }
        require(valid) { "Rule bundle signature is invalid." }

        val rules = mutableListOf<ContentSignatureRule>()
        var previousId: String? = null
        var totalPatternBytes = 0
        for (line in lines.subList(5, lines.lastIndex)) {
            require(line.startsWith("rule=")) { "Unexpected rule-bundle field." }
            val fields = line.removePrefix("rule=").split('|')
            require(fields.size == 10) { "Invalid rule entry." }
            val id = fields[0]
            val family = fields[1]
            val groupId = fields[2]
            val minimumGroupMatches = fields[3].toIntOrNull()
                ?: throw IllegalArgumentException("Invalid rule-group threshold.")
            val classification = ThreatClassification.entries.firstOrNull { it.name == fields[4] }
                ?: throw IllegalArgumentException("Invalid rule classification.")
            val confidence = fields[5].toIntOrNull()
                ?: throw IllegalArgumentException("Invalid rule confidence.")
            val sourceId = fields[6]
            val licenseId = fields[7]
            require(
                idPattern.matches(id) && id != "ALAI-NATIVE-ENGINE-SELFTEST" &&
                    (previousId == null || id > previousId)
            ) {
                "Rule IDs must be valid, sorted, unique, and not reserved."
            }
            require(
                familyPattern.matches(family) && familyPattern.matches(groupId) &&
                    sourcePattern.matches(sourceId) && licensePattern.matches(licenseId) &&
                    confidence in 1..100 && minimumGroupMatches in 1..MAX_RULES
            ) { "Invalid rule metadata, group threshold, or missing provenance/license." }
            val pattern = Base64.getUrlDecoder().decode(fields[8])
            require(Base64.getUrlEncoder().withoutPadding().encodeToString(pattern) == fields[8]) {
                "Non-canonical rule pattern encoding."
            }
            require(pattern.size in 4..MAX_PATTERN_BYTES) { "Rule pattern length is outside policy." }
            totalPatternBytes += pattern.size
            require(totalPatternBytes <= MAX_TOTAL_PATTERN_BYTES) { "Rule patterns exceed the total size limit." }
            val descriptionBytes = Base64.getUrlDecoder().decode(fields[9])
            val description = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(descriptionBytes)).toString()
            require(description.isNotBlank() && description.length <= 240) { "Invalid rule description." }
            rules += ContentSignatureRule(
                id = id,
                familyId = family,
                classification = classification,
                confidence = confidence,
                pattern = pattern,
                description = description,
                sourceId = sourceId,
                licenseId = licenseId,
                groupId = groupId,
                minimumGroupMatches = minimumGroupMatches
            )
            previousId = id
            require(rules.size <= MAX_RULES) { "Too many content rules." }
        }
        require(rules.isNotEmpty()) { "Refusing an empty content-rule bundle." }

        val groups = rules.groupBy { it.groupId }
        groups.forEach { (groupId, members) ->
            val first = members.first()
            require(members.size >= first.minimumGroupMatches) {
                "Rule group $groupId has fewer entries than its required match threshold."
            }
            require(members.all { member ->
                member.familyId == first.familyId &&
                    member.minimumGroupMatches == first.minimumGroupMatches &&
                    member.classification == first.classification &&
                    member.confidence == first.confidence &&
                    member.sourceId == first.sourceId &&
                    member.licenseId == first.licenseId
            }) { "Rule group $groupId has inconsistent metadata." }
        }
        return SignedContentRuleBundle(keyId, version, issued, expires, rules)
    }

    private fun parsePositive(line: String, prefix: String): Long {
        require(line.startsWith(prefix)) { "Missing $prefix field." }
        val raw = line.removePrefix(prefix)
        require(longPattern.matches(raw)) { "Invalid $prefix value." }
        return raw.toLongOrNull() ?: throw IllegalArgumentException("Out-of-range $prefix value.")
    }
}

object ContentRuleBundleRuntime {
    const val FEED_URL =
        "https://raw.githubusercontent.com/karafarin12800-del/ANTIVIRUS-AL-Ai/security-feed/content-rules/latest.alrules"
    private const val MAX_DOWNLOAD_BYTES = ContentRuleBundleParser.MAX_BUNDLE_BYTES
    private const val DIRECTORY = "content-rules"
    private const val FILE_NAME = "current.alrules"
    private const val VERSION_NAME = "highest-version.txt"
    private val cacheLock = Any()
    @Volatile private var cachedBundle: SignedContentRuleBundle? = null
    @Volatile private var cachedLength: Long = -1L
    @Volatile private var cachedModified: Long = -1L

    fun state(context: Context): ContentRuleBundleState {
        val file = File(context.applicationContext.filesDir, "$DIRECTORY/$FILE_NAME")
        if (!file.isFile) return ContentRuleBundleState.MISSING
        if (file.length() !in 1L..ContentRuleBundleParser.MAX_BUNDLE_BYTES.toLong()) {
            return ContentRuleBundleState.INVALID
        }
        return try {
            ContentRuleBundleParser.parse(
                file.readBytes(),
                minimumVersionExclusive = (readVersion(context) - 1L).coerceAtLeast(0L)
            )
            ContentRuleBundleState.CURRENT
        } catch (error: Exception) {
            if (error.message?.contains("expired", ignoreCase = true) == true) {
                ContentRuleBundleState.EXPIRED
            } else {
                ContentRuleBundleState.INVALID
            }
        }
    }

    fun current(context: Context): SignedContentRuleBundle? {
        val file = File(context.applicationContext.filesDir, "$DIRECTORY/$FILE_NAME")
        if (!file.isFile || file.length() !in 1L..ContentRuleBundleParser.MAX_BUNDLE_BYTES.toLong()) return null
        synchronized(cacheLock) {
            val length = file.length()
            val modified = file.lastModified()
            val cached = cachedBundle
            if (cachedLength == length && cachedModified == modified &&
                cached?.expiresAtEpochSeconds?.let { it > System.currentTimeMillis() / 1000L } == true
            ) return cached
            val loaded = runCatching {
                ContentRuleBundleParser.parse(
                    file.readBytes(),
                    minimumVersionExclusive = (readVersion(context) - 1L).coerceAtLeast(0L)
                )
            }.getOrNull()
            cachedBundle = loaded
            cachedLength = length
            cachedModified = modified
            return loaded
        }
    }

    suspend fun refresh(context: Context): SignedContentRuleBundle = withContext(Dispatchers.IO) {
        val url = URL(FEED_URL)
        require(url.protocol.equals("https", true) && url.host.equals("raw.githubusercontent.com", true))
        val connection = (url.openConnection() as HttpsURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 15_000
            readTimeout = 20_000
            useCaches = false
            instanceFollowRedirects = false
            setRequestProperty("Accept", "text/plain")
            setRequestProperty("Cache-Control", "no-cache")
        }
        try {
            check(connection.responseCode == HttpsURLConnection.HTTP_OK) {
                "No signed content-rule bundle is published yet."
            }
            val bytes = connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= MAX_DOWNLOAD_BYTES) { "Content-rule bundle exceeds its size limit." }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            install(context, bytes)
        } finally {
            connection.disconnect()
        }
    }

    @Synchronized
    fun install(context: Context, bytes: ByteArray): SignedContentRuleBundle {
        val appContext = context.applicationContext
        val directory = File(appContext.filesDir, DIRECTORY)
        if (!directory.exists() && !directory.mkdirs()) {
            throw IllegalStateException("Could not create content-rule storage.")
        }
        val currentVersion = readVersion(context)
        val parsed = ContentRuleBundleParser.parse(bytes, minimumVersionExclusive = currentVersion)
        val target = File(directory, FILE_NAME)
        val versionFile = File(directory, VERSION_NAME)
        writeAtomically(directory, target, bytes)
        writeAtomically(directory, versionFile, (parsed.version.toString() + "\n").toByteArray(StandardCharsets.US_ASCII))
        synchronized(cacheLock) {
            cachedBundle = parsed
            cachedLength = target.length()
            cachedModified = target.lastModified()
        }
        return parsed
    }

    private fun readVersion(context: Context): Long {
        val file = File(context.applicationContext.filesDir, "$DIRECTORY/$VERSION_NAME")
        if (!file.isFile) return 0L
        val raw = file.readText(StandardCharsets.US_ASCII).trim()
        require(raw.matches(Regex("[1-9][0-9]{0,18}"))) { "Stored rule-bundle version is invalid." }
        return raw.toLongOrNull() ?: throw IllegalArgumentException("Stored rule-bundle version is out of range.")
    }

    private fun writeAtomically(directory: File, target: File, bytes: ByteArray) {
        val temp = File.createTempFile("rules-", ".tmp", directory)
        try {
            FileOutputStream(temp).use { output -> output.write(bytes); output.fd.sync() }
            try {
                Files.move(temp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            temp.delete()
        }
    }
}

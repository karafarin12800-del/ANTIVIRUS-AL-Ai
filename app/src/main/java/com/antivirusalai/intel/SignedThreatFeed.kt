package com.antivirusalai.intel

import java.io.File
import java.io.FileOutputStream
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

enum class ThreatClassification { MALWARE, PUA, SUSPICIOUS }

enum class ThreatIndicatorType { URL, DOMAIN, IPV4, IP_PORT }

data class ThreatIndicator(
    val sha256: String,
    val familyId: String,
    val classification: ThreatClassification,
    val sources: Set<String> = setOf("LEGACY"),
    val confidence: Int = 0,
    val firstSeenAtEpochSeconds: Long = 0L,
    val expiresAtEpochSeconds: Long = 0L
)

data class ThreatNetworkIndicator(
    val type: ThreatIndicatorType,
    val value: String,
    val familyId: String,
    val classification: ThreatClassification,
    val sources: Set<String>,
    val confidence: Int,
    val firstSeenAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long
)

data class SignedThreatFeed(
    val keyId: String,
    val version: Long,
    val issuedAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val indicators: Map<String, ThreatIndicator>,
    val networkIndicators: Map<String, ThreatNetworkIndicator> = emptyMap(),
    val sourceCounts: Map<String, Int> = emptyMap(),
    val truncated: Boolean = false
)

enum class FeedValidationCode {
    FEED_TOO_LARGE,
    INVALID_UTF8,
    INVALID_STRUCTURE,
    INVALID_SIGNATURE,
    INVALID_FIELD,
    INVALID_INDICATOR,
    DUPLICATE_OR_UNSORTED_INDICATOR,
    TOO_MANY_INDICATORS,
    FEED_EXPIRED,
    FEED_ISSUED_IN_FUTURE,
    INVALID_FEED_LIFETIME,
    VERSION_ROLLBACK,
    STORAGE_FAILURE
}

class FeedValidationException(
    val code: FeedValidationCode,
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

/** Verifies the exact UTF-8 payload bytes; key identifiers select pinned public keys. */
fun interface FeedSignatureVerifier {
    fun verify(keyId: String, payload: ByteArray, signature: ByteArray): Boolean
}

/**
 * ECDSA P-256 / SHA-256 keyring. Only public X.509 SubjectPublicKeyInfo keys belong here.
 * Never place feed-signing private keys in the Android app or this repository.
 */
class EcdsaP256KeyringVerifier(keys: Map<String, PublicKey>) : FeedSignatureVerifier {
    private val trustedKeys = keys.toMap()

    init {
        require(trustedKeys.isNotEmpty()) { "At least one trusted public key is required." }
        trustedKeys.forEach { (keyId, key) ->
            require(KEY_ID_PATTERN.matches(keyId)) { "Invalid key identifier." }
            require(key is ECPublicKey && key.params.curve.field.fieldSize == 256) {
                "Only ECDSA P-256 public keys are accepted."
            }
        }
    }

    override fun verify(keyId: String, payload: ByteArray, signature: ByteArray): Boolean {
        val key = trustedKeys[keyId] ?: return false
        return try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(payload)
                verify(signature)
            }
        } catch (_: Exception) {
            false
        }
    }

    companion object {
        private val KEY_ID_PATTERN = Regex("[A-Za-z0-9._-]{1,40}")

        fun decodeX509PublicKey(base64: String): PublicKey {
            val encoded = try {
                Base64.getDecoder().decode(base64)
            } catch (error: IllegalArgumentException) {
                throw IllegalArgumentException("The public key is not valid Base64.", error)
            }
            return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded))
        }
    }
}

object SignedThreatFeedParser {
    const val FORMAT_HEADER = "ALAI-THREAT-FEED/1"
    const val MULTI_SOURCE_FORMAT_HEADER = "ALAI-THREAT-FEED/2"
    const val MAX_FEED_BYTES = 4 * 1024 * 1024
    const val MAX_INDICATORS = 20_000
    const val MAX_VALIDITY_SECONDS = 30L * 24L * 60L * 60L
    private const val ALLOWED_CLOCK_SKEW_SECONDS = 5L * 60L
    private val KEY_ID_PATTERN = Regex("[A-Za-z0-9._-]{1,40}")
    private val HASH_PATTERN = Regex("[0-9a-f]{64}")
    private val FAMILY_PATTERN = Regex("[A-Z0-9][A-Z0-9._-]{0,79}")
    private val SOURCE_PATTERN = Regex("[A-Z0-9][A-Z0-9._-]{0,39}")
    private val POSITIVE_LONG_PATTERN = Regex("[1-9][0-9]{0,18}")
    private val CONFIDENCE_PATTERN = Regex("(?:0|[1-9][0-9]{0,2})")
    private val DOMAIN_PATTERN = Regex("(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

    fun parse(
        bytes: ByteArray,
        verifier: FeedSignatureVerifier,
        nowEpochSeconds: Long,
        minimumVersionExclusive: Long = 0L
    ): SignedThreatFeed {
        if (bytes.isEmpty() || bytes.size > MAX_FEED_BYTES) {
            fail(FeedValidationCode.FEED_TOO_LARGE, "Threat feed is empty or exceeds 4 MiB.")
        }
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        } catch (error: CharacterCodingException) {
            throw FeedValidationException(FeedValidationCode.INVALID_UTF8, "Feed is not valid UTF-8.", error)
        }
        if (text.contains('\r') || !text.endsWith('\n')) {
            fail(FeedValidationCode.INVALID_STRUCTURE, "Feed must use LF line endings and end with a newline.")
        }
        val lines = text.dropLast(1).split('\n')
        if (lines.size < 5) fail(FeedValidationCode.INVALID_STRUCTURE, "Feed is missing required fields.")
        val legacy = lines[0] == FORMAT_HEADER
        val multi = lines[0] == MULTI_SOURCE_FORMAT_HEADER
        if (!legacy && !multi) fail(FeedValidationCode.INVALID_STRUCTURE, "Unsupported threat-feed format.")

        val signatureLine = lines.last()
        if (!signatureLine.startsWith("signature=")) fail(FeedValidationCode.INVALID_STRUCTURE, "Signature must be final line.")
        val signatureBytes = try {
            Base64.getDecoder().decode(signatureLine.removePrefix("signature="))
        } catch (error: IllegalArgumentException) {
            throw FeedValidationException(FeedValidationCode.INVALID_STRUCTURE, "Signature is not valid Base64.", error)
        }
        val signedPayload = lines.dropLast(1).joinToString("\n", postfix = "\n").toByteArray(StandardCharsets.UTF_8)
        if (!lines[1].startsWith("key_id=")) fail(FeedValidationCode.INVALID_STRUCTURE, "Missing key identifier.")
        val keyId = lines[1].removePrefix("key_id=")
        if (!KEY_ID_PATTERN.matches(keyId)) fail(FeedValidationCode.INVALID_FIELD, "Invalid key identifier.")
        if (!verifier.verify(keyId, signedPayload, signatureBytes)) {
            fail(FeedValidationCode.INVALID_SIGNATURE, "Signature invalid or key untrusted.")
        }

        val version = parsePositiveLong(lines[2], "version=")
        val issued = parsePositiveLong(lines[3], "issued_at=")
        val expires = parsePositiveLong(lines[4], "expires_at=")
        if (version <= minimumVersionExclusive) fail(FeedValidationCode.VERSION_ROLLBACK, "Feed version rollback.")
        if (issued > nowEpochSeconds + ALLOWED_CLOCK_SKEW_SECONDS) {
            fail(FeedValidationCode.FEED_ISSUED_IN_FUTURE, "Feed issue time is in the future.")
        }
        if (expires <= nowEpochSeconds) fail(FeedValidationCode.FEED_EXPIRED, "Feed has expired.")
        if (expires <= issued || expires - issued > MAX_VALIDITY_SECONDS) {
            fail(FeedValidationCode.INVALID_FEED_LIFETIME, "Feed lifetime is invalid.")
        }

        var cursor = 5
        val sourceCounts = linkedMapOf<String, Int>()
        var truncated = false
        if (multi) {
            var previousSource: String? = null
            while (cursor < lines.lastIndex && lines[cursor].startsWith("source_count=")) {
                val fields = lines[cursor].removePrefix("source_count=").split('|')
                if (fields.size != 2) fail(FeedValidationCode.INVALID_STRUCTURE, "Invalid source-count field.")
                val source = fields[0]
                if (!SOURCE_PATTERN.matches(source) || (previousSource != null && source <= previousSource)) {
                    fail(FeedValidationCode.INVALID_FIELD, "Source identifiers must be sorted and unique.")
                }
                val count = fields[1].toIntOrNull()
                if (count == null || count !in 0..MAX_INDICATORS) {
                    fail(FeedValidationCode.INVALID_FIELD, "Invalid source count.")
                }
                sourceCounts[source] = count
                previousSource = source
                cursor++
            }
            if (sourceCounts.isEmpty() || cursor >= lines.lastIndex || !lines[cursor].startsWith("feed_truncated=")) {
                fail(FeedValidationCode.INVALID_STRUCTURE, "Incomplete multi-source metadata.")
            }
            truncated = when (lines[cursor].removePrefix("feed_truncated=")) {
                "0" -> false
                "1" -> true
                else -> fail(FeedValidationCode.INVALID_FIELD, "Invalid truncation marker.")
            }
            cursor++
        }

        val hashes = LinkedHashMap<String, ThreatIndicator>()
        val network = LinkedHashMap<String, ThreatNetworkIndicator>()
        val observedCounts = sourceCounts.keys.associateWith { 0 }.toMutableMap()
        var previousKey: String? = null
        val entryLines = lines.subList(cursor, lines.lastIndex)
        if (entryLines.size > MAX_INDICATORS) fail(FeedValidationCode.TOO_MANY_INDICATORS, "Too many indicators.")

        for (line in entryLines) {
            if (!line.startsWith("entry=")) fail(FeedValidationCode.INVALID_STRUCTURE, "Unexpected entry data.")
            val fields = line.removePrefix("entry=").split('|')
            val kind: String
            val value: String
            val family: String
            val classification: ThreatClassification
            val sources: Set<String>
            val confidence: Int
            val firstSeen: Long
            val itemExpires: Long
            if (legacy) {
                if (fields.size != 3) fail(FeedValidationCode.INVALID_INDICATOR, "Invalid legacy entry.")
                kind = "SHA256"
                value = fields[0]
                family = fields[1]
                classification = ThreatClassification.entries.firstOrNull { it.name == fields[2] }
                    ?: fail(FeedValidationCode.INVALID_INDICATOR, "Invalid classification.")
                sources = setOf("LEGACY")
                confidence = 0
                firstSeen = issued
                itemExpires = expires
            } else {
                if (fields.size != 8) fail(FeedValidationCode.INVALID_INDICATOR, "Invalid typed entry.")
                kind = fields[0]
                val encoded = fields[1]
                val decoded = try {
                    Base64.getUrlDecoder().decode(encoded)
                } catch (error: IllegalArgumentException) {
                    throw FeedValidationException(FeedValidationCode.INVALID_INDICATOR, "IOC value is not Base64URL.", error)
                }
                if (Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != encoded) {
                    fail(FeedValidationCode.INVALID_INDICATOR, "IOC value encoding is not canonical.")
                }
                value = try {
                    StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(java.nio.ByteBuffer.wrap(decoded)).toString()
                } catch (error: CharacterCodingException) {
                    throw FeedValidationException(FeedValidationCode.INVALID_INDICATOR, "IOC value is not UTF-8.", error)
                }
                family = fields[2]
                classification = ThreatClassification.entries.firstOrNull { it.name == fields[3] }
                    ?: fail(FeedValidationCode.INVALID_INDICATOR, "Invalid IOC classification.")
                val sourceParts = fields[4].split(',')
                if (sourceParts.isEmpty() || sourceParts.any { !SOURCE_PATTERN.matches(it) } ||
                    sourceParts.distinct().size != sourceParts.size || sourceParts != sourceParts.sorted()
                ) fail(FeedValidationCode.INVALID_FIELD, "Invalid IOC provenance.")
                sources = sourceParts.toSet()
                if (sources.any { it !in sourceCounts }) fail(FeedValidationCode.INVALID_FIELD, "Undeclared IOC source.")
                if (!CONFIDENCE_PATTERN.matches(fields[5])) fail(FeedValidationCode.INVALID_FIELD, "Invalid confidence.")
                confidence = fields[5].toIntOrNull() ?: fail(FeedValidationCode.INVALID_FIELD, "Invalid confidence.")
                if (confidence > 100) fail(FeedValidationCode.INVALID_FIELD, "Confidence must be 0..100.")
                firstSeen = parsePositiveLong("first_seen=" + fields[6], "first_seen=")
                itemExpires = parsePositiveLong("expires_at=" + fields[7], "expires_at=")
                if (firstSeen > nowEpochSeconds + ALLOWED_CLOCK_SKEW_SECONDS ||
                    itemExpires <= nowEpochSeconds || itemExpires <= firstSeen || itemExpires > expires
                ) fail(FeedValidationCode.INVALID_FIELD, "Invalid IOC timestamps.")
            }
            if (!FAMILY_PATTERN.matches(family)) fail(FeedValidationCode.INVALID_INDICATOR, "Invalid family identifier.")
            val key = kind + "|" + value
            if (previousKey != null && key <= previousKey) {
                fail(FeedValidationCode.DUPLICATE_OR_UNSORTED_INDICATOR, "Entries must be uniquely sorted by type and value.")
            }
            previousKey = key

            if (kind == "SHA256") {
                if (!HASH_PATTERN.matches(value)) fail(FeedValidationCode.INVALID_INDICATOR, "Invalid SHA-256.")
                hashes[value] = ThreatIndicator(value, family, classification, sources, confidence, firstSeen, itemExpires)
            } else {
                val type = ThreatIndicatorType.entries.firstOrNull { it.name == kind }
                    ?: fail(FeedValidationCode.INVALID_INDICATOR, "Unsupported IOC type.")
                if (!validNetworkValue(type, value)) fail(FeedValidationCode.INVALID_INDICATOR, "Invalid network IOC value.")
                network[type.name + "|" + value] = ThreatNetworkIndicator(
                    type, value, family, classification, sources, confidence, firstSeen, itemExpires
                )
            }
            if (multi) sources.forEach { observedCounts[it] = (observedCounts[it] ?: 0) + 1 }
        }
        if (multi && observedCounts != sourceCounts) {
            fail(FeedValidationCode.INVALID_STRUCTURE, "Source counts do not match signed indicators.")
        }
        return SignedThreatFeed(
            keyId, version, issued, expires, hashes, network, sourceCounts, truncated
        )
    }

    private fun validNetworkValue(type: ThreatIndicatorType, value: String): Boolean = when (type) {
        ThreatIndicatorType.URL -> runCatching {
            val uri = java.net.URI(value)
            uri.isAbsolute && (uri.scheme.equals("http", true) || uri.scheme.equals("https", true)) &&
                !uri.host.isNullOrBlank() && uri.rawUserInfo == null && uri.rawFragment == null &&
                value.length <= 2048 && value.none { it.isWhitespace() || it.code < 0x20 }
        }.getOrDefault(false)
        ThreatIndicatorType.DOMAIN -> DOMAIN_PATTERN.matches(value) && !value.contains("..")
        ThreatIndicatorType.IPV4 -> validIpv4(value)
        ThreatIndicatorType.IP_PORT -> {
            val split = value.lastIndexOf(':')
            if (split <= 0 || split == value.lastIndex) false else {
                val port = value.substring(split + 1).toIntOrNull()
                validIpv4(value.substring(0, split)) && port != null && port in 1..65535
            }
        }
    }

    private fun validIpv4(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() && (part == "0" || !part.startsWith('0')) &&
                part.all { it in '0'..'9' } && part.toIntOrNull()?.let { it in 0..255 } == true
        }
    }

    private fun parsePositiveLong(line: String, prefix: String): Long {
        if (!line.startsWith(prefix)) fail(FeedValidationCode.INVALID_STRUCTURE, "Required numeric field missing.")
        val raw = line.removePrefix(prefix)
        if (!POSITIVE_LONG_PATTERN.matches(raw)) fail(FeedValidationCode.INVALID_FIELD, "Invalid numeric field.")
        return raw.toLongOrNull() ?: fail(FeedValidationCode.INVALID_FIELD, "Numeric field out of range.")
    }

    private fun fail(code: FeedValidationCode, message: String): Nothing =
        throw FeedValidationException(code, message)
}

/**
 * Private-directory feed storage with atomic replacement and a persistent
 * monotonic version floor. The caller must pass an app-private directory.
 */
class SignedThreatFeedStore(
    private val directory: File,
    private val verifier: FeedSignatureVerifier,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000L }
) {
    private val feedFile = File(directory, "current.alfeed")
    private val versionFile = File(directory, "highest-version")

    @Synchronized
    fun install(bytes: ByteArray): SignedThreatFeed {
        val floor = readHighestVersion()
        val parsed = SignedThreatFeedParser.parse(
            bytes = bytes,
            verifier = verifier,
            nowEpochSeconds = clock(),
            minimumVersionExclusive = floor
        )

        try {
            if (!directory.exists() && !directory.mkdirs()) {
                throw IllegalStateException("Could not create the threat-feed directory.")
            }
            // Advance the rollback floor first. A crash can temporarily disable the old feed,
            // but can never make an older feed acceptable again.
            writeAtomically(versionFile, "${parsed.version}\n".toByteArray(StandardCharsets.US_ASCII))
            writeAtomically(feedFile, bytes)
        } catch (error: Exception) {
            throw FeedValidationException(
                FeedValidationCode.STORAGE_FAILURE,
                "The verified threat feed could not be stored safely.",
                error
            )
        }
        return parsed
    }

    @Synchronized
    fun loadCurrent(): SignedThreatFeed? {
        if (!feedFile.isFile) return null
        val floor = readHighestVersion()
        return SignedThreatFeedParser.parse(
            bytes = try {
                feedFile.readBytes()
            } catch (error: Exception) {
                throw FeedValidationException(
                    FeedValidationCode.STORAGE_FAILURE,
                    "The stored threat feed could not be read.",
                    error
                )
            },
            verifier = verifier,
            nowEpochSeconds = clock(),
            minimumVersionExclusive = (floor - 1L).coerceAtLeast(0L)
        )
    }

    fun lookup(sha256: String): ThreatIndicator? {
        if (!Regex("[0-9a-fA-F]{64}").matches(sha256)) return null
        return loadCurrent()?.indicators?.get(sha256.lowercase())
    }

    private fun readHighestVersion(): Long {
        if (!versionFile.exists()) return 0L
        val raw = try {
            versionFile.readText(StandardCharsets.US_ASCII).removeSuffix("\n")
        } catch (error: Exception) {
            throw FeedValidationException(
                FeedValidationCode.STORAGE_FAILURE,
                "The saved threat-feed version cannot be read.",
                error
            )
        }
        if (!Regex("[1-9][0-9]{0,18}").matches(raw)) {
            fail(FeedValidationCode.STORAGE_FAILURE, "The saved threat-feed version is invalid.")
        }
        return raw.toLongOrNull()
            ?: fail(FeedValidationCode.STORAGE_FAILURE, "The saved threat-feed version is out of range.")
    }

    private fun writeAtomically(target: File, bytes: ByteArray) {
        val temporary = File.createTempFile("feed-", ".tmp", directory)
        try {
            FileOutputStream(temporary).use { output ->
                output.write(bytes)
                output.fd.sync()
            }
            try {
                Files.move(
                    temporary.toPath(),
                    target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(
                    temporary.toPath(),
                    target.toPath(),
                    StandardCopyOption.REPLACE_EXISTING
                )
            }
        } finally {
            temporary.delete()
        }
    }

    private fun fail(code: FeedValidationCode, message: String): Nothing =
        throw FeedValidationException(code, message)
}

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

data class ThreatIndicator(
    val sha256: String,
    val familyId: String,
    val classification: ThreatClassification
)

data class SignedThreatFeed(
    val keyId: String,
    val version: Long,
    val issuedAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val indicators: Map<String, ThreatIndicator>
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
    const val MAX_FEED_BYTES = 2 * 1024 * 1024
    const val MAX_INDICATORS = 20_000
    const val MAX_VALIDITY_SECONDS = 30L * 24L * 60L * 60L
    private const val ALLOWED_CLOCK_SKEW_SECONDS = 5L * 60L
    private val KEY_ID_PATTERN = Regex("[A-Za-z0-9._-]{1,40}")
    private val HASH_PATTERN = Regex("[0-9a-f]{64}")
    private val FAMILY_PATTERN = Regex("[A-Z0-9][A-Z0-9._-]{0,79}")
    private val POSITIVE_LONG_PATTERN = Regex("[1-9][0-9]{0,18}")

    /**
     * Feed layout is strict and canonical. The signature covers every byte up to,
     * but not including, the final signature= line.
     */
    fun parse(
        bytes: ByteArray,
        verifier: FeedSignatureVerifier,
        nowEpochSeconds: Long,
        minimumVersionExclusive: Long = 0L
    ): SignedThreatFeed {
        if (bytes.isEmpty() || bytes.size > MAX_FEED_BYTES) {
            fail(FeedValidationCode.FEED_TOO_LARGE, "The threat feed is empty or exceeds 2 MiB.")
        }

        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes))
                .toString()
        } catch (error: CharacterCodingException) {
            throw FeedValidationException(
                FeedValidationCode.INVALID_UTF8,
                "The threat feed is not valid UTF-8.",
                error
            )
        }

        if (text.contains('\r') || !text.endsWith('\n')) {
            fail(FeedValidationCode.INVALID_STRUCTURE, "The feed must use LF line endings and end with a newline.")
        }

        val lines = text.dropLast(1).split('\n')
        if (lines.size < 5) {
            fail(FeedValidationCode.INVALID_STRUCTURE, "The feed is missing required fields.")
        }

        val signatureLine = lines.last()
        if (!signatureLine.startsWith("signature=")) {
            fail(FeedValidationCode.INVALID_STRUCTURE, "The signature must be the final feed line.")
        }
        val signatureText = signatureLine.removePrefix("signature=")
        if (signatureText.isEmpty()) {
            fail(FeedValidationCode.INVALID_STRUCTURE, "The feed signature is missing.")
        }
        val signatureBytes = try {
            Base64.getDecoder().decode(signatureText)
        } catch (error: IllegalArgumentException) {
            throw FeedValidationException(
                FeedValidationCode.INVALID_STRUCTURE,
                "The feed signature is not valid Base64.",
                error
            )
        }

        val signedPayload = lines.dropLast(1).joinToString(separator = "\n", postfix = "\n")
            .toByteArray(StandardCharsets.UTF_8)

        // Read only the key id needed to choose a trusted key; all fields are authenticated below.
        if (lines[0] != FORMAT_HEADER || !lines[1].startsWith("key_id=")) {
            fail(FeedValidationCode.INVALID_STRUCTURE, "Unsupported feed format or missing key identifier.")
        }
        val keyId = lines[1].removePrefix("key_id=")
        if (!KEY_ID_PATTERN.matches(keyId)) {
            fail(FeedValidationCode.INVALID_FIELD, "The signing key identifier is invalid.")
        }
        if (!verifier.verify(keyId, signedPayload, signatureBytes)) {
            fail(
                FeedValidationCode.INVALID_SIGNATURE,
                "The feed signature is invalid or the signing key is not trusted."
            )
        }

        if (lines.size < 5 || lines[0] != FORMAT_HEADER) {
            fail(FeedValidationCode.INVALID_STRUCTURE, "The feed header is invalid.")
        }
        val version = parsePositiveLong(lines[2], "version=")
        val issuedAt = parsePositiveLong(lines[3], "issued_at=")
        val expiresAt = parsePositiveLong(lines[4], "expires_at=")

        if (version <= minimumVersionExclusive) {
            fail(FeedValidationCode.VERSION_ROLLBACK, "The feed version is not newer than the stored version.")
        }
        if (issuedAt > nowEpochSeconds + ALLOWED_CLOCK_SKEW_SECONDS) {
            fail(FeedValidationCode.FEED_ISSUED_IN_FUTURE, "The feed issue time is too far in the future.")
        }
        if (expiresAt <= nowEpochSeconds) {
            fail(FeedValidationCode.FEED_EXPIRED, "The signed threat feed has expired.")
        }
        if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_VALIDITY_SECONDS) {
            fail(FeedValidationCode.INVALID_FEED_LIFETIME, "The feed validity period is invalid.")
        }

        val indicators = LinkedHashMap<String, ThreatIndicator>()
        var previousHash: String? = null
        val entryLines = lines.subList(5, lines.lastIndex)
        if (entryLines.size > MAX_INDICATORS) {
            fail(FeedValidationCode.TOO_MANY_INDICATORS, "The feed contains too many indicators.")
        }

        for (line in entryLines) {
            if (!line.startsWith("entry=")) {
                fail(FeedValidationCode.INVALID_STRUCTURE, "Unexpected data in the indicator section.")
            }
            val fields = line.removePrefix("entry=").split('|')
            if (fields.size != 3) {
                fail(FeedValidationCode.INVALID_INDICATOR, "An indicator entry has an invalid field count.")
            }
            val hash = fields[0]
            val familyId = fields[1]
            val classification = ThreatClassification.entries.firstOrNull { it.name == fields[2] }
            if (!HASH_PATTERN.matches(hash) || !FAMILY_PATTERN.matches(familyId) || classification == null) {
                fail(FeedValidationCode.INVALID_INDICATOR, "An indicator contains an invalid hash, family, or class.")
            }
            if (previousHash != null && hash <= previousHash) {
                fail(
                    FeedValidationCode.DUPLICATE_OR_UNSORTED_INDICATOR,
                    "Indicator hashes must be unique and sorted in ascending order."
                )
            }
            previousHash = hash
            indicators[hash] = ThreatIndicator(hash, familyId, classification)
        }

        return SignedThreatFeed(
            keyId = keyId,
            version = version,
            issuedAtEpochSeconds = issuedAt,
            expiresAtEpochSeconds = expiresAt,
            indicators = indicators
        )
    }

    private fun parsePositiveLong(line: String, prefix: String): Long {
        if (!line.startsWith(prefix)) {
            fail(FeedValidationCode.INVALID_STRUCTURE, "A required numeric field is missing.")
        }
        val raw = line.removePrefix(prefix)
        if (!POSITIVE_LONG_PATTERN.matches(raw)) {
            fail(FeedValidationCode.INVALID_FIELD, "A numeric feed field is invalid.")
        }
        return raw.toLongOrNull()
            ?: fail(FeedValidationCode.INVALID_FIELD, "A numeric feed field is out of range.")
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

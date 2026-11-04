package com.antivirusalai.intel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class SignedThreatFeedTest {
    private val now = 1_800_000_000L
    private val keyId = "release-test-2026"

    private fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }

    private fun verifier(pair: KeyPair, id: String = keyId) =
        EcdsaP256KeyringVerifier(mapOf(id to pair.public))

    private fun signedFeed(
        pair: KeyPair,
        version: Long,
        issuedAt: Long = now - 60,
        expiresAt: Long = now + 86_400,
        entries: List<Triple<String, String, String>> = listOf(
            Triple("a".repeat(64), "TEST.FAMILY", "MALWARE")
        ),
        id: String = keyId
    ): ByteArray {
        val payload = buildString {
            append(SignedThreatFeedParser.FORMAT_HEADER).append('\n')
            append("key_id=").append(id).append('\n')
            append("version=").append(version).append('\n')
            append("issued_at=").append(issuedAt).append('\n')
            append("expires_at=").append(expiresAt).append('\n')
            entries.sortedBy { it.first }.forEach { (hash, family, classification) ->
                append("entry=").append(hash).append('|')
                    .append(family).append('|').append(classification).append('\n')
            }
        }.toByteArray(StandardCharsets.UTF_8)

        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(pair.private)
            update(payload)
            sign()
        }
        return payload + "signature=${Base64.getEncoder().encodeToString(signature)}\n"
            .toByteArray(StandardCharsets.UTF_8)
    }

    private fun expectCode(expected: FeedValidationCode, action: () -> Unit) {
        try {
            action()
            fail("Expected FeedValidationException with code $expected.")
        } catch (error: FeedValidationException) {
            assertEquals(expected, error.code)
        }
    }

    @Test
    fun acceptsValidSignedFeedAndParsesIndicator() {
        val pair = keyPair()
        val feed = SignedThreatFeedParser.parse(
            signedFeed(pair, version = 1),
            verifier(pair),
            nowEpochSeconds = now
        )

        assertEquals(1L, feed.version)
        assertEquals(keyId, feed.keyId)
        assertEquals(1, feed.indicators.size)
        assertEquals(
            ThreatClassification.MALWARE,
            feed.indicators["a".repeat(64)]?.classification
        )
    }

    @Test
    fun rejectsPayloadTampering() {
        val pair = keyPair()
        val changed = String(signedFeed(pair, version = 1), StandardCharsets.UTF_8)
            .replace("version=1\n", "version=2\n")
            .toByteArray(StandardCharsets.UTF_8)

        expectCode(FeedValidationCode.INVALID_SIGNATURE) {
            SignedThreatFeedParser.parse(changed, verifier(pair), now)
        }
    }

    @Test
    fun rejectsUnknownKeyId() {
        val signingPair = keyPair()
        val otherPair = keyPair()
        expectCode(FeedValidationCode.INVALID_SIGNATURE) {
            SignedThreatFeedParser.parse(
                signedFeed(signingPair, version = 1),
                verifier(otherPair, id = "another-key"),
                now
            )
        }
    }

    @Test
    fun rejectsExpiredFeed() {
        val pair = keyPair()
        expectCode(FeedValidationCode.FEED_EXPIRED) {
            SignedThreatFeedParser.parse(
                signedFeed(pair, version = 1, issuedAt = now - 100_000, expiresAt = now - 1),
                verifier(pair),
                now
            )
        }
    }

    @Test
    fun rejectsFeedIssuedTooFarInFuture() {
        val pair = keyPair()
        expectCode(FeedValidationCode.FEED_ISSUED_IN_FUTURE) {
            SignedThreatFeedParser.parse(
                signedFeed(pair, version = 1, issuedAt = now + 301, expiresAt = now + 86_400),
                verifier(pair),
                now
            )
        }
    }

    @Test
    fun rejectsDuplicateOrUnsortedIndicatorHashes() {
        val pair = keyPair()
        val duplicate = listOf(
            Triple("a".repeat(64), "FAMILY.A", "MALWARE"),
            Triple("a".repeat(64), "FAMILY.B", "PUA")
        )
        expectCode(FeedValidationCode.DUPLICATE_OR_UNSORTED_INDICATOR) {
            SignedThreatFeedParser.parse(
                signedFeed(pair, version = 1, entries = duplicate),
                verifier(pair),
                now
            )
        }
    }

    @Test
    fun rejectsRollbackVersion() {
        val pair = keyPair()
        expectCode(FeedValidationCode.VERSION_ROLLBACK) {
            SignedThreatFeedParser.parse(
                signedFeed(pair, version = 4),
                verifier(pair),
                now,
                minimumVersionExclusive = 4
            )
        }
    }

    @Test
    fun storePersistsFeedAndRejectsReplayAfterRecreation() {
        val pair = keyPair()
        val directory = Files.createTempDirectory("alai-threat-feed-").toFile()
        try {
            val firstStore = SignedThreatFeedStore(directory, verifier(pair)) { now }
            firstStore.install(signedFeed(pair, version = 1))
            assertNotNull(firstStore.lookup("A".repeat(64)))

            val restartedStore = SignedThreatFeedStore(directory, verifier(pair)) { now }
            assertEquals(1L, restartedStore.loadCurrent()?.version)
            expectCode(FeedValidationCode.VERSION_ROLLBACK) {
                restartedStore.install(signedFeed(pair, version = 1))
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun unknownHashIsNotReportedByFeedStore() {
        val pair = keyPair()
        val directory = kotlin.io.path.createTempDirectory("alai-threat-feed-").toFile()
        try {
            val store = SignedThreatFeedStore(directory, verifier(pair)) { now }
            store.install(signedFeed(pair, version = 1))
            assertNull(store.lookup("b".repeat(64)))
            assertNull(store.lookup("not-a-sha256"))
        } finally {
            directory.deleteRecursively()
        }
    }
}

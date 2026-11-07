package com.antivirusalai.intel

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.URL
import java.security.PublicKey
import javax.net.ssl.HttpsURLConnection

/**
 * Loads only feeds authenticated by the app-pinned release public key.
 * No file contents, samples, or private data are sent to the feed publisher.
 */
object ThreatFeedRuntime {
    const val RELEASE_KEY_ID = "alai-release-2026"
    const val FEED_URL =
        "https://raw.githubusercontent.com/karafarin12800-del/ANTIVIRUS-AL-Ai/security-feed/threat-feed/latest.alfeed"

    // Public X.509 P-256 key only. Never package the matching private signing key.
    private const val RELEASE_PUBLIC_KEY_X509_B64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAzDOX+WcMzHRxjHa/zC4ZHIUePAR3IxTWtedJPzrM/sov5xWIWbvlnw/WBJczc6Jix9ccV5Z2EqgfKfLaQrNhg=="

    private val hashPattern = Regex("[0-9a-fA-F]{64}")
    private val cacheLock = Any()

    @Volatile
    private var cachedFeed: SignedThreatFeed? = null

    @Volatile
    private var cachedFileLength: Long = -1L

    @Volatile
    private var cachedFileModified: Long = -1L

    private fun verifier(): FeedSignatureVerifier {
        val key: PublicKey =
            EcdsaP256KeyringVerifier.decodeX509PublicKey(RELEASE_PUBLIC_KEY_X509_B64)
        return EcdsaP256KeyringVerifier(mapOf(RELEASE_KEY_ID to key))
    }

    private fun store(context: Context): SignedThreatFeedStore =
        SignedThreatFeedStore(
            File(context.applicationContext.filesDir, "threat-intelligence"),
            verifier()
        )

    /** Null means no valid, current signed feed is available; it never means clean. */
    fun lookup(context: Context, sha256: String): ThreatIndicator? {
        if (!hashPattern.matches(sha256)) return null
        return currentFeed(context)?.indicators?.get(sha256.lowercase())
    }

    fun currentFeed(context: Context): SignedThreatFeed? {
        val file = File(context.applicationContext.filesDir, "threat-intelligence/current.alfeed")
        if (!file.isFile) return null
        synchronized(cacheLock) {
            val length = file.length()
            val modified = file.lastModified()
            val cached = cachedFeed
            val now = System.currentTimeMillis() / 1000L
            if (cached != null &&
                cachedFileLength == length &&
                cachedFileModified == modified &&
                cached.expiresAtEpochSeconds > now
            ) return cached

            val loaded = runCatching { store(context).loadCurrent() }.getOrNull()
            cachedFeed = loaded
            cachedFileLength = length
            cachedFileModified = modified
            return loaded
        }
    }

    suspend fun refresh(context: Context): SignedThreatFeed = withContext(Dispatchers.IO) {
        val url = URL(FEED_URL)
        require(url.protocol.equals("https", ignoreCase = true))
        require(url.host.equals("raw.githubusercontent.com", ignoreCase = true))

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
                "Signed threat feed is not published yet or the server is unavailable."
            }

            val bytes = connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= SignedThreatFeedParser.MAX_FEED_BYTES) {
                        "Threat feed exceeds the 2 MiB safety limit."
                    }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }

            // install() verifies signature, key ID, expiry, entry order and rollback
            // before atomically replacing the previously accepted feed.
            val installed = store(context).install(bytes)
            synchronized(cacheLock) {
                val file = File(context.applicationContext.filesDir, "threat-intelligence/current.alfeed")
                cachedFeed = installed
                cachedFileLength = file.length()
                cachedFileModified = file.lastModified()
            }
            installed
        } finally {
            connection.disconnect()
        }
    }
}

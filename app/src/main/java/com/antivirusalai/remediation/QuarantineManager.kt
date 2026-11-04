package com.antivirusalai.remediation

import android.content.Context
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

data class QuarantineReceipt(val id: String, val sizeBytes: Long, val sha256: String)

object QuarantineManager {
    private const val KEY_ALIAS = "antivirus_al_ai_quarantine_v1"
    private val MAGIC = "ALAIQ1".toByteArray(Charsets.US_ASCII)
    private const val MAX_SIZE = 200L * 1024L * 1024L

    /**
     * Writes an AES-GCM encrypted copy in app-private storage and verifies the
     * plaintext SHA-256. The selected source is intentionally not deleted.
     */
    suspend fun saveEncryptedCopy(
        context: Context,
        source: Uri,
        expectedSha256: String
    ): QuarantineReceipt = withContext(Dispatchers.IO) {
        val directory = File(context.filesDir, "quarantine")
        check(directory.exists() || directory.mkdirs()) {
            "Could not create the private quarantine directory."
        }

        val id = UUID.randomUUID().toString()
        val temporary = File.createTempFile("incoming-", ".part", directory)
        val destination = File(directory, "$id.alaiq")
        val digest = MessageDigest.getInstance("SHA-256")
        var totalBytes = 0L

        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())

            val input = context.contentResolver.openInputStream(source)
                ?: throw IllegalStateException("Android could not reopen the selected file.")

            input.use { sourceStream ->
                FileOutputStream(temporary).use { fileStream ->
                    fileStream.write(MAGIC)
                    fileStream.write(cipher.iv.size)
                    fileStream.write(cipher.iv)

                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = sourceStream.read(buffer)
                        if (count < 0) break
                        totalBytes += count
                        require(totalBytes <= MAX_SIZE) {
                            "File exceeds the 200 MB quarantine limit."
                        }
                        digest.update(buffer, 0, count)
                        val encrypted = cipher.update(buffer, 0, count)
                        if (encrypted != null) fileStream.write(encrypted)
                    }

                    fileStream.write(cipher.doFinal())
                    fileStream.fd.sync()
                }
            }

            val actualHash = digest.digest().joinToString("") {
                "%02x".format(it.toInt() and 0xff)
            }
            check(actualHash.equals(expectedSha256, ignoreCase = true)) {
                "The source file changed after scanning. The quarantine copy was discarded."
            }

            try {
                Files.move(temporary.toPath(), destination.toPath(), StandardCopyOption.ATOMIC_MOVE)
            } catch (_: Exception) {
                check(temporary.renameTo(destination)) {
                    "Could not finalize the encrypted quarantine copy."
                }
            }

            QuarantineReceipt(id = id, sizeBytes = totalBytes, sha256 = actualHash)
        } catch (error: Exception) {
            temporary.delete()
            destination.delete()
            throw error
        }
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }
}

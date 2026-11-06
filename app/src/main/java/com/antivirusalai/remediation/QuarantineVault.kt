package com.antivirusalai.remediation

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Properties
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class VaultReceipt(
    val id: String,
    val sizeBytes: Long,
    val sha256: String,
    val sourceRemoved: Boolean
)

data class VaultEntry(
    val id: String,
    val sizeBytes: Long,
    val sha256: String
)

/**
 * App-private AES-GCM quarantine vault. Source removal is a separate,
 * explicit operation and is attempted only after a verified copy exists.
 */
object QuarantineVault {
    private const val KEY_ALIAS = "antivirus_al_ai_quarantine_v2"
    private val MAGIC = "ALAIQ2".toByteArray(Charsets.US_ASCII)
    private const val MAX_SIZE = 200L * 1024L * 1024L
    private const val IV_SIZE = 12
    private const val TAG_BITS = 128
    private val idPattern = Regex("[0-9a-fA-F-]{36}")
    private val hashPattern = Regex("[0-9a-f]{64}")

    suspend fun quarantineAndRemoveSource(
        context: Context,
        source: Uri,
        expectedSha256: String
    ): VaultReceipt = withContext(Dispatchers.IO) {
        require(hashPattern.matches(expectedSha256.lowercase())) { "Expected SHA-256 is invalid." }
        val receipt = saveVerifiedCopy(context, source, expectedSha256)
        val currentHash = runCatching { hashSource(context, source) }.getOrNull()
        if (!currentHash.equals(receipt.sha256, ignoreCase = true)) {
            return@withContext receipt.copy(sourceRemoved = false)
        }
        val removed = runCatching { deleteSource(context, source) }.getOrDefault(false)
        receipt.copy(sourceRemoved = removed)
    }

    suspend fun saveVerifiedCopy(
        context: Context,
        source: Uri,
        expectedSha256: String
    ): VaultReceipt = withContext(Dispatchers.IO) {
        require(hashPattern.matches(expectedSha256.lowercase())) { "Expected SHA-256 is invalid." }
        val directory = directory(context)
        val id = UUID.randomUUID().toString()
        val encrypted = File(directory, "$id.alaiq")
        val metadata = File(directory, "$id.meta")
        val temporary = File.createTempFile("incoming-", ".part", directory)
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L

        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            val input = openSource(context, source)

            input.use { sourceStream ->
                FileOutputStream(temporary).use { output ->
                    output.write(MAGIC)
                    output.write(cipher.iv.size)
                    output.write(cipher.iv)
                    val buffer = ByteArray(8192)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = sourceStream.read(buffer)
                        if (count < 0) break
                        total += count
                        require(total <= MAX_SIZE) { "File exceeds the 200 MB quarantine limit." }
                        digest.update(buffer, 0, count)
                        cipher.update(buffer, 0, count)?.let(output::write)
                    }
                    output.write(cipher.doFinal())
                    output.fd.sync()
                }
            }

            val actualHash = digest.digest().toHex()
            check(actualHash == expectedSha256.lowercase()) {
                "Source changed after scanning. No source file was removed."
            }

            atomicMove(temporary, encrypted)
            writeMetadata(metadata, total, actualHash)
            VaultReceipt(id, total, actualHash, sourceRemoved = false)
        } catch (error: Exception) {
            temporary.delete()
            encrypted.delete()
            metadata.delete()
            throw error
        }
    }

    fun list(context: Context): List<VaultEntry> {
        val dir = directory(context)
        return dir.listFiles { f -> f.isFile && f.name.endsWith(".meta") }
            .orEmpty()
            .mapNotNull { meta ->
                val id = meta.name.removeSuffix(".meta")
                if (!idPattern.matches(id)) return@mapNotNull null
                readEntry(dir, id)
            }
            .sortedByDescending { it.id }
    }

    /**
     * Decrypts and authenticates into a private temporary file before writing
     * to the user's restore destination.
     */
    suspend fun restoreTo(context: Context, id: String, destination: Uri): VaultEntry =
        withContext(Dispatchers.IO) {
            require(idPattern.matches(id)) { "Quarantine identifier is invalid." }
            val dir = directory(context)
            val entry = readEntry(dir, id) ?: error("Quarantine item was not found.")
            val encrypted = File(dir, "$id.alaiq")
            val temporary = File.createTempFile("alai-restore-", ".tmp", context.cacheDir)
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L

            try {
                DataInputStream(FileInputStream(encrypted).buffered()).use { input ->
                    val magic = ByteArray(MAGIC.size)
                    input.readFully(magic)
                    check(magic.contentEquals(MAGIC)) { "Quarantine header is invalid." }
                    val ivLength = input.readUnsignedByte()
                    check(ivLength == IV_SIZE) { "Quarantine IV is invalid." }
                    val iv = ByteArray(ivLength)
                    input.readFully(iv)

                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(
                        Cipher.DECRYPT_MODE,
                        getOrCreateKey(),
                        GCMParameterSpec(TAG_BITS, iv)
                    )

                    FileOutputStream(temporary).use { output ->
                        val buffer = ByteArray(8192)
                        while (true) {
                            currentCoroutineContext().ensureActive()
                            val count = input.read(buffer)
                            if (count < 0) break
                            val plain = cipher.update(buffer, 0, count)
                            if (plain != null && plain.isNotEmpty()) {
                                total += plain.size
                                require(total <= MAX_SIZE) { "Quarantine item exceeds restore limit." }
                                digest.update(plain)
                                output.write(plain)
                            }
                        }
                        val tail = cipher.doFinal()
                        if (tail.isNotEmpty()) {
                            total += tail.size
                            require(total <= MAX_SIZE) { "Quarantine item exceeds restore limit." }
                            digest.update(tail)
                            output.write(tail)
                        }
                        output.fd.sync()
                    }
                }

                check(total == entry.sizeBytes && digest.digest().toHex() == entry.sha256) {
                    "Quarantine integrity check failed. Nothing was restored."
                }

                val output = if (destination.scheme == "file") {
                    FileOutputStream(File(destination.path ?: error("Restore path is invalid.")))
                } else {
                    context.contentResolver.openOutputStream(destination, "wt")
                        ?: error("Android could not open the restore destination.")
                }
                output.use { target ->
                    temporary.inputStream().use { input -> input.copyTo(target) }
                    target.flush()
                }
                entry
            } finally {
                temporary.delete()
            }
        }

    /** Deletes only the selected encrypted copy; flash storage cannot guarantee secure overwrite. */
    fun delete(context: Context, id: String): Boolean {
        require(idPattern.matches(id)) { "Quarantine identifier is invalid." }
        val dir = directory(context)
        val encrypted = File(dir, "$id.alaiq")
        val metadata = File(dir, "$id.meta")
        if (!encrypted.exists() && !metadata.exists()) return false
        val encryptedDeleted = !encrypted.exists() || encrypted.delete()
        val metadataDeleted = !metadata.exists() || metadata.delete()
        return encryptedDeleted && metadataDeleted
    }

    private fun directory(context: Context): File =
        File(context.applicationContext.filesDir, "quarantine-v2").also {
            check(it.exists() || it.mkdirs()) { "Could not create private quarantine storage." }
        }

    private fun writeMetadata(file: File, size: Long, hash: String) {
        val temp = File.createTempFile("meta-", ".part", file.parentFile)
        try {
            val properties = Properties().apply {
                setProperty("size", size.toString())
                setProperty("sha256", hash)
            }
            FileOutputStream(temp).use { output ->
                properties.store(output, "ANTIVIRUS AL AI quarantine receipt")
                output.fd.sync()
            }
            atomicMove(temp, file)
        } finally {
            temp.delete()
        }
    }

    private fun readEntry(dir: File, id: String): VaultEntry? {
        val metadata = File(dir, "$id.meta")
        val encrypted = File(dir, "$id.alaiq")
        if (!metadata.isFile || !encrypted.isFile) return null
        return runCatching {
            val props = Properties().apply { metadata.inputStream().use(::load) }
            val size = props.getProperty("size")?.toLongOrNull() ?: return null
            val hash = props.getProperty("sha256") ?: return null
            if (size < 0 || !hashPattern.matches(hash)) return null
            VaultEntry(id, size, hash)
        }.getOrNull()
    }

    private fun openSource(context: Context, source: Uri) =
        if (source.scheme == "file") {
            FileInputStream(File(source.path ?: error("Source path is invalid.")))
        } else {
            context.contentResolver.openInputStream(source)
                ?: error("Android could not open the source file.")
        }

    private fun hashSource(context: Context, source: Uri): String {
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        openSource(context, source).use { input ->
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                require(total <= MAX_SIZE) { "Source exceeds quarantine limit." }
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().toHex()
    }

    private fun deleteSource(context: Context, source: Uri): Boolean =
        if (source.scheme == "file") {
            File(source.path ?: return false).delete()
        } else if (DocumentsContract.isDocumentUri(context, source)) {
            DocumentsContract.deleteDocument(context.contentResolver, source)
        } else {
            context.contentResolver.delete(source, null, null) > 0
        }

    private fun atomicMove(source: File, destination: File) {
        try {
            java.nio.file.Files.move(
                source.toPath(),
                destination.toPath(),
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING
            )
        } catch (_: Exception) {
            check(source.renameTo(destination)) { "Could not finalize quarantine file." }
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

    private fun ByteArray.toHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}

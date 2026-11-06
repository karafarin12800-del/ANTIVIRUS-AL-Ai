package com.antivirusalai

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.antivirusalai.remediation.QuarantineVault
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class QuarantineVaultInstrumentedTest {
    @Test
    fun encryptedQuarantineCanBeListedRestoredAndRemoved() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val payload = ByteArray(32_791) { index -> ((index * 31) % 251).toByte() }
        val source = File(context.cacheDir, "quarantine-source-${UUID.randomUUID()}.bin")
        val restored = File(context.cacheDir, "quarantine-restored-${UUID.randomUUID()}.bin")
        source.writeBytes(payload)
        val expectedHash = sha256(payload)
        var entryId: String? = null

        try {
            val receipt = QuarantineVault.quarantineAndRemoveSource(
                context,
                Uri.fromFile(source),
                expectedHash
            )
            entryId = receipt.id

            assertEquals(payload.size.toLong(), receipt.sizeBytes)
            assertEquals(expectedHash, receipt.sha256)
            assertTrue("The source should only be removed after a verified vault copy exists.", receipt.sourceRemoved)
            assertFalse("The test source should be removed after the explicit quarantine operation.", source.exists())

            val listed = QuarantineVault.list(context).firstOrNull { it.id == receipt.id }
            assertNotNull("A valid quarantine entry should be listed.", listed)

            val restoredEntry = QuarantineVault.restoreTo(
                context,
                receipt.id,
                Uri.fromFile(restored)
            )
            assertEquals(expectedHash, restoredEntry.sha256)
            assertArrayEquals("Restored bytes must exactly match the verified source.", payload, restored.readBytes())

            assertTrue("The selected vault entry should be deletable.", QuarantineVault.delete(context, receipt.id))
            assertTrue("Deleted vault entries must not remain listed.", QuarantineVault.list(context).none { it.id == receipt.id })
        } finally {
            entryId?.let { QuarantineVault.delete(context, it) }
            source.delete()
            restored.delete()
        }
    }

    @Test
    fun hashMismatchDoesNotCreateAQuarantineEntryOrDeleteTheSource() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val source = File(context.cacheDir, "quarantine-mismatch-${UUID.randomUUID()}.bin")
        source.writeBytes("safe test fixture".toByteArray(Charsets.UTF_8))
        val before = QuarantineVault.list(context).map { it.id }.toSet()

        try {
            var rejected = false
            try {
                QuarantineVault.saveVerifiedCopy(
                    context,
                    Uri.fromFile(source),
                    "0".repeat(64)
                )
            } catch (_: IllegalStateException) {
                rejected = true
            }

            assertTrue("A hash mismatch must reject the copy.", rejected)
            assertTrue("A failed quarantine attempt must leave the source untouched.", source.exists())
            assertEquals("A failed copy must not leave a visible quarantine record.", before, QuarantineVault.list(context).map { it.id }.toSet())
        } finally {
            source.delete()
        }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }
}

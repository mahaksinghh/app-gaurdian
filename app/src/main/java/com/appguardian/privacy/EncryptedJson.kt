package com.appguardian.privacy

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

internal class EncryptedJson(context: Context, name: String) {
    private val file = AtomicFile(File(context.noBackupFilesDir, name))
    private val associatedData = "appguardian:$name:v1".toByteArray()

    fun read(): JSONObject = synchronized(storageLock) { readLocked() }

    fun update(transform: (JSONObject) -> JSONObject): JSONObject =
        synchronized(storageLock) {
            val next = transform(readLocked())
            val clear = next.toString().toByteArray()
            if (clear.size > MAX_CLEAR_BYTES) throw IOException("Private storage limit reached.")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(associatedData)
            val encrypted = cipher.doFinal(clear)
            val stream = file.startWrite()
            try {
                stream.write(cipher.iv)
                stream.write(encrypted)
                file.finishWrite(stream)
            } catch (error: Exception) {
                file.failWrite(stream)
                throw error
            }
            next
        }

    fun clear() = synchronized(storageLock) { file.delete() }

    private fun readLocked(): JSONObject {
        val packet = try {
            file.openRead().use { input ->
                val size = input.channel.size()
                if (size < NONCE_SIZE + TAG_SIZE || size > MAX_CLEAR_BYTES + NONCE_SIZE + TAG_SIZE) {
                    throw IOException("Invalid private storage size.")
                }
                input.readBytes()
            }
        } catch (_: FileNotFoundException) {
            return JSONObject()
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_SIZE * 8, packet, 0, NONCE_SIZE))
        cipher.updateAAD(associatedData)
        val clear = cipher.doFinal(packet, NONCE_SIZE, packet.size - NONCE_SIZE)
        return JSONObject(clear.toString(Charsets.UTF_8))
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE)
        store.load(null)
        val existing = store.getKey(ALIAS, null) as? SecretKey
        if (existing != null) return existing
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private companion object {
        val storageLock = Any()
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "appguardian.private.storage.v1"
        const val NONCE_SIZE = 12
        const val TAG_SIZE = 16
        const val MAX_CLEAR_BYTES = 512 * 1024
    }
}

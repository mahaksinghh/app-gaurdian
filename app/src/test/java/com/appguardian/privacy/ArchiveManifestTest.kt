package com.appguardian.privacy

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Test

class ArchiveManifestTest {
    @Test(expected = IOException::class)
    fun rejectsChunkBeyondDocumentBounds() {
        val xml = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(3).putShort(8).putInt(16)
            .putShort(1).putShort(28).putInt(Int.MAX_VALUE)
            .array()

        BinaryManifest(xml).readApplication()
    }
}

package com.appguardian.privacy

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

internal data class ArchiveManifest(
    val debuggable: Boolean = false,
    val testOnly: Boolean = false,
    val cleartextOptIn: Boolean = false
) {
    companion object {
        private const val NAME = "AndroidManifest.xml"
        private const val MAX_BYTES = 1024 * 1024

        fun read(apk: File): ArchiveManifest = ZipFile(apk).use { archive ->
            val entry = archive.getEntry(NAME) ?: throw IOException("APK manifest is missing.")
            if (entry.isDirectory || entry.size !in 1L..MAX_BYTES.toLong()) invalidManifest()
            val size = entry.size.toInt()
            val bytes = archive.getInputStream(entry).use { source ->
                val output = ByteArrayOutputStream(size)
                val buffer = ByteArray(8192)
                var remaining = size
                while (remaining > 0) {
                    val count = source.read(buffer, 0, minOf(buffer.size, remaining))
                    if (count <= 0) invalidManifest()
                    output.write(buffer, 0, count)
                    remaining -= count
                }
                if (source.read() != -1) invalidManifest()
                output.toByteArray()
            }
            BinaryManifest(bytes).readApplication()
        }
    }
}

private fun invalidManifest(): Nothing = throw IOException("Malformed or unsupported Android manifest.")

// ResChunk_header, ResStringPool_header and ResXMLTree_* in Android's ResourceTypes.h.
internal class BinaryManifest(private val bytes: ByteArray) {
    private val data = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

    fun readApplication(): ArchiveManifest {
        val root = chunk(0, data.limit())
        if (root.type != XML || root.end != data.limit()) invalidManifest()

        var cursor = root.body
        var strings: Strings? = null
        var depth = 0
        var sawManifest = false
        var application: ArchiveManifest? = null
        while (cursor < root.end) {
            val child = chunk(cursor, root.end)
            when (child.type) {
                STRING_POOL -> {
                    if (strings != null || sawManifest) invalidManifest()
                    strings = Strings(child)
                }
                START_ELEMENT -> {
                    val pool = strings ?: invalidManifest()
                    if (child.body - child.start < 16) invalidManifest()
                    range(child.body, 20, child.end)
                    val tag = pool.read(data.getInt(child.body + 4))
                    val unqualified = data.getInt(child.body) == -1
                    if (depth == 0) {
                        if (sawManifest || !unqualified || tag != "manifest") invalidManifest()
                        sawManifest = true
                    }
                    if (depth == 1 && unqualified && tag == "application") {
                        if (application != null) invalidManifest()
                        application = readFlags(child, pool)
                    }
                    depth++
                }
                END_ELEMENT -> {
                    if (depth == 0) invalidManifest()
                    depth--
                }
            }
            cursor = child.end
        }
        if (depth != 0 || !sawManifest) invalidManifest()
        return application ?: ArchiveManifest()
    }

    private fun readFlags(element: Chunk, strings: Strings): ArchiveManifest {
        val start = unsignedShort(element.body + 8)
        val size = unsignedShort(element.body + 10)
        val count = unsignedShort(element.body + 12)
        if (start < 20 || size < 20 || start > element.end - element.body) invalidManifest()
        val first = element.body + start
        if (count > (element.end - first) / size) invalidManifest()

        val flags = mutableSetOf<String>()
        repeat(count) { index ->
            val at = first + index * size
            val namespace = data.getInt(at)
            if (namespace == -1 || strings.read(namespace) != ANDROID_NS) return@repeat
            val name = strings.read(data.getInt(at + 4))
            if (name !in APPLICATION_FLAGS) return@repeat
            if (unsignedShort(at + 12) != 8) invalidManifest()
            if ((data.get(at + 15).toInt() and 0xff) == TYPE_BOOLEAN && data.getInt(at + 16) != 0) {
                flags.add(name)
            }
        }
        return ArchiveManifest("debuggable" in flags, "testOnly" in flags, "usesCleartextTraffic" in flags)
    }

    private inner class Strings(pool: Chunk) {
        private val count: Int
        private val offsets = pool.body
        private val base: Int
        private val limit: Int
        private val utf8: Boolean

        init {
            if (pool.body - pool.start < 28) invalidManifest()
            count = data.getInt(pool.start + 8)
            val styles = data.getInt(pool.start + 12)
            if (count < 0 || styles < 0) invalidManifest()
            utf8 = data.getInt(pool.start + 16) and 0x100 != 0
            val stringsStart = data.getInt(pool.start + 20)
            val stylesStart = data.getInt(pool.start + 24)
            range(pool.start, stringsStart, pool.end)
            base = pool.start + stringsStart
            if (base < offsets || (count.toLong() + styles) * 4 > base - offsets) invalidManifest()
            limit = if (stylesStart == 0) {
                pool.end
            } else {
                range(pool.start, stylesStart, pool.end)
                (pool.start + stylesStart).also { if (it < base) invalidManifest() }
            }
        }

        fun read(index: Int): String {
            if (index !in 0 until count) invalidManifest()
            val offset = data.getInt(offsets + 4 * index)
            if (offset < 0 || offset >= limit - base) invalidManifest()
            val at = base + offset
            val (start, count) = if (utf8) {
                val (_, next) = length(at, 1)
                val (bytes, content) = length(next, 1)
                content to bytes
            } else {
                val (units, content) = length(at, 2)
                if (units > (limit - content) / 2) invalidManifest()
                content to units * 2
            }
            val terminator = if (utf8) 1 else 2
            range(start, count, limit - terminator)
            val end = start + count
            if (data.get(end).toInt() != 0 || (!utf8 && data.get(end + 1).toInt() != 0)) invalidManifest()
            // The names and namespace this reader compares are short ASCII strings.
            if (count > 128) return ""
            return String(bytes, start, count, if (utf8) Charsets.UTF_8 else Charsets.UTF_16LE)
        }

        private fun length(at: Int, width: Int): Pair<Int, Int> {
            range(at, width, limit)
            val bits = width * 8 - 1
            val flag = 1 shl bits
            val first = if (width == 1) data.get(at).toInt() and 0xff else unsignedShort(at)
            if (first and flag == 0) return first to at + width
            range(at, width * 2, limit)
            val next = at + width
            val second = if (width == 1) data.get(next).toInt() and 0xff else unsignedShort(next)
            return ((first and (flag - 1)) shl (width * 8) or second) to (next + width)
        }
    }

    private data class Chunk(val type: Int, val start: Int, val body: Int, val end: Int)

    private fun chunk(at: Int, limit: Int): Chunk {
        range(at, 8, limit)
        val header = unsignedShort(at + 2)
        val size = data.getInt(at + 4)
        if (header < 8 || size < header) invalidManifest()
        range(at, size, limit)
        return Chunk(unsignedShort(at), at, at + header, at + size)
    }

    private fun range(start: Int, length: Int, limit: Int) {
        if (start < 0 || length < 0 || start > limit || length > limit - start) invalidManifest()
    }

    private fun unsignedShort(at: Int): Int = data.getShort(at).toInt() and 0xffff

    private companion object {
        const val XML = 0x0003
        const val STRING_POOL = 0x0001
        const val START_ELEMENT = 0x0102
        const val END_ELEMENT = 0x0103
        const val TYPE_BOOLEAN = 0x12
        const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
        val APPLICATION_FLAGS = setOf("debuggable", "testOnly", "usesCleartextTraffic")
    }
}

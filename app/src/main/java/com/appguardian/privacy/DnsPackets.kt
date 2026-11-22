package com.appguardian.privacy

import java.net.IDN
import java.util.Locale

internal object DomainRules {
    fun parse(input: String): Set<String> {
        require(input.length <= 8192) { "Enter at most 8,192 characters." }
        val entries = input.lineSequence().map(String::trim).filter(String::isNotEmpty).toList()
        require(entries.size <= 100) { "Enter up to 100 domains." }
        return entries.map { raw ->
            val name = IDN.toASCII(raw.trimEnd('.'), IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
            require(name.length in 3..253 && '.' in name && name.split('.').all { it.length in 1..63 }) {
                "Enter domains without paths, ports or wildcards."
            }
            name
        }.toSet()
    }

    fun blocks(host: String, rules: Set<String>): Boolean = rules.any { host == it || host.endsWith(".$it") }
}

internal object DnsPackets {
    const val MTU = 1500
    const val MAX_DNS = MTU - 28
    private val gateway = byteArrayOf(10, 211.toByte(), 0, 2)

    data class Query(
        val peer: ByteArray,
        val port: Int,
        val payload: ByteArray,
        val questionEnd: Int,
        val hostname: String
    )

    fun decode(packet: ByteArray, length: Int): Query? {
        if (length !in 40..minOf(packet.size, MTU) || packet[0].toInt() ushr 4 != 4) return null
        val header = (packet[0].toInt() and 15) * 4
        if (header < 20 || length < header + 20 || packet[9] != 17.toByte() ||
            word(packet, 2) != length || word(packet, 6) and 0x3fff != 0
        ) return null
        if (!packet.copyOfRange(16, 20).contentEquals(gateway) || word(packet, header + 2) != 53) return null
        if (word(packet, header + 4) != length - header) return null

        val dns = packet.copyOfRange(header + 8, length)
        if (dns[2].toInt() and 0xf8 != 0 || word(dns, 4) != 1) return null
        var offset = 12
        val labels = mutableListOf<String>()
        while (offset < dns.size) {
            val size = dns[offset++].toInt() and 0xff
            if (size == 0) {
                if (offset > dns.size - 4 || offset > 267) return null
                return Query(packet.copyOfRange(12, 16), word(packet, header), dns, offset + 4, labels.joinToString("."))
            }
            if (size > 63 || offset > dns.size - size || offset + size > 267) return null
            val label = dns.decodeToString(offset, offset + size).lowercase(Locale.ROOT)
            if (!label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) return null
            labels.add(label)
            offset += size
        }
        return null
    }

    fun error(query: Query, code: Int): ByteArray =
        query.payload.copyOf(query.questionEnd).also { dns ->
            dns[2] = ((dns[2].toInt() and 1) or 0x80).toByte()
            dns[3] = (0x80 or code).toByte()
            dns.fill(0, 6, 12)
        }

    fun reply(query: Query, dns: ByteArray): ByteArray {
        require(dns.size in 12..MAX_DNS)
        val packet = ByteArray(28 + dns.size)
        packet[0] = 0x45
        putWord(packet, 2, packet.size)
        packet[8] = 64
        packet[9] = 17
        gateway.copyInto(packet, 12)
        query.peer.copyInto(packet, 16)
        var total = 0
        for (offset in 0 until 20 step 2) total += word(packet, offset)
        while (total > 0xffff) total = (total and 0xffff) + (total ushr 16)
        putWord(packet, 10, total.inv() and 0xffff)
        putWord(packet, 20, 53)
        putWord(packet, 22, query.port)
        putWord(packet, 24, dns.size + 8)
        dns.copyInto(packet, 28)
        return packet
    }

    private fun word(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun putWord(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }
}

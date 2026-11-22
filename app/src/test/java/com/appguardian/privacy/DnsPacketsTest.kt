package com.appguardian.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsPacketsTest {
    @Test fun selectedDomainsMatchOnlyOnLabelBoundaries() {
        val rules = DomainRules.parse(" Example.COM.\nbücher.example")
        assertEquals(setOf("example.com", "xn--bcher-kva.example"), rules)
        assertTrue(DomainRules.blocks("sub.example.com", rules))
        assertTrue(DomainRules.blocks("example.com", rules))
        assertFalse(DomainRules.blocks("otherexample.com", rules))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsNonDomainInput() {
        DomainRules.parse("example.com/path")
    }

    @Test fun blockedReplyPreservesQuestionAndReversesAddressAndPorts() {
        val packet = ipv4Query()
        val query = checkNotNull(DnsPackets.decode(packet, packet.size))
        assertEquals("example.com", query.hostname)
        val reply = DnsPackets.reply(query, DnsPackets.error(query, 3))
        assertEquals(53, readWord(reply, 20))
        assertEquals(42, readWord(reply, 22))
        assertEquals("10.211.0.1", reply.slice(16..19).joinToString(".") { (it.toInt() and 255).toString() })
        assertEquals(0x1234, readWord(reply, 28))
        assertEquals(3, reply[31].toInt() and 15)
        assertEquals(1, readWord(reply, 32))
        assertEquals(0, readWord(reply, 34))
        val headerSum = (0 until 20 step 2).sumOf { readWord(reply, it) }
        assertEquals(0xffff, (headerSum and 0xffff) + (headerSum ushr 16))
    }

    @Test fun malformedOrUnrelatedPacketsAreIgnored() {
        val truncated = ipv4Query()
        assertNull(DnsPackets.decode(truncated, truncated.size - 1))
        assertNull(DnsPackets.decode(truncated.copyOf().also { it[9] = 6 }, truncated.size))
        assertNull(DnsPackets.decode(truncated.copyOf().also { it[40] = 0xc0.toByte() }, truncated.size))
    }

    private fun ipv4Query(): ByteArray {
        val domain = byteArrayOf(7) + "example".toByteArray() + byteArrayOf(3) + "com".toByteArray()
        val dns = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            domain + byteArrayOf(0, 0, 1, 0, 1)
        return ByteArray(28 + dns.size).apply {
            this[0] = 0x45
            this[3] = size.toByte()
            this[9] = 17
            byteArrayOf(10, 211.toByte(), 0, 1, 10, 211.toByte(), 0, 2).copyInto(this, 12)
            this[21] = 42
            this[23] = 53
            this[25] = (dns.size + 8).toByte()
            dns.copyInto(this, 28)
        }
    }

    private fun readWord(bytes: ByteArray, offset: Int) =
        ((bytes[offset].toInt() and 255) shl 8) or (bytes[offset + 1].toInt() and 255)
}

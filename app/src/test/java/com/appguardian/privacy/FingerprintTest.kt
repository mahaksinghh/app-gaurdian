package com.appguardian.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FingerprintTest {
    @Test fun normalizesPublisherFingerprints() {
        assertEquals("ab".repeat(32), List(32) { "AB" }.joinToString(": ").let(::normalizeFingerprint))
        assertNull(normalizeFingerprint("aa".repeat(31)))
        assertNull(normalizeFingerprint("gz".repeat(32)))
    }
}

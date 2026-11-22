package com.appguardian.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CloudEndpointTest {
    @Test fun acceptsHttpsWithOptionalPathPrefix() {
        assertEquals("https://example.test/guardian", parseEndpoint(" https://example.test/guardian/ "))
    }

    @Test fun rejectsInsecureOrAmbiguousEndpoints() {
        listOf(
            "http://example.test", "https://name:secret@example.test",
            "https://example.test#anchor", "https://example.test?session=abc",
            "https://example.test:65536", "file:///tmp/guardian"
        ).forEach { endpoint ->
            assertThrows(IllegalArgumentException::class.java) { parseEndpoint(endpoint) }
        }
    }
}

package com.appguardian.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceTest {
    @Test fun unknownPermissionsDoNotCreateFindings() {
        assertTrue(Evidence.review(setOf("publisher.permission.READ_SMS"), false, false).isEmpty())
    }

    @Test fun findingsAreStableAndEvidenceBased() {
        val permissions = setOf("android.permission.RECORD_AUDIO", "android.permission.READ_SMS")
        val findings = Evidence.review(permissions, true, true)
        assertEquals(listOf("READ_SMS", "RECORD_AUDIO", "Accessibility service", "Debuggable build"), findings.map { it.title })
        assertEquals(findings, Evidence.review(permissions.reversed().toSet(), true, true))
    }

    @Test fun comparisonReportsOnlyChangedGrants() {
        assertEquals(
            listOf("Granted: CAMERA", "Revoked: READ_SMS"),
            Evidence.changedGrants(setOf("READ_SMS", "INTERNET"), setOf("CAMERA", "INTERNET"))
        )
    }
}

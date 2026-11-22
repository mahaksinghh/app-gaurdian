package com.appguardian.privacy

import android.content.ContentValues
import android.content.Intent
import android.graphics.Bitmap
import android.os.Build
import android.os.SystemClock
import android.provider.MediaStore
import android.util.Base64
import android.view.accessibility.AccessibilityNodeInfo
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PilotIntegrationTest {
    @get:Rule val screen = createAndroidComposeRule<MainActivity>()
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val arguments get() = InstrumentationRegistry.getArguments()

    @Test
    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.Q)
    fun emulatorConnectsToIsolatedBackendOverHttps() {
        val endpoint = arguments.getString("pilotUrl")
        val pem = arguments.getString("pilotCertificate")
        val enrollment = arguments.getString("pilotEnrollment")
        assumeTrue(endpoint != null && pem != null && enrollment != null)
        val context = instrumentation.targetContext
        val previousTls = HttpsURLConnection.getDefaultSSLSocketFactory()
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(Base64.decode(checkNotNull(pem), Base64.DEFAULT).inputStream())
        val trust = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("pilot", certificate)
        }
        val manager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
        val testTls = SSLContext.getInstance("TLS").apply { init(null, manager.trustManagers, null) }
        // Trust the ephemeral CI certificate in this test process only. Hostname validation remains active.
        HttpsURLConnection.setDefaultSSLSocketFactory(testTls.socketFactory)

        val client = CloudClient(context)
        val email = "android-${UUID.randomUUID()}@example.test"
        val password = "guardian-ci-integration-password"
        val resolver = context.contentResolver
        val apk = File(context.applicationInfo.sourceDir)
        val document = checkNotNull(resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, "AppGuardian-integration.apk")
            put(MediaStore.Downloads.MIME_TYPE, "application/vnd.android.package-archive")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }))

        try {
            val session = client.signIn(checkNotNull(endpoint), email, password, enrollment)
            assertTrue(session.activeToken() != null)
            val installed = checkNotNull(PackageReview(context).installed(context.packageName))
            client.save(session, installed, shareDashboard = true)
            assertEquals(listOf(context.packageName), client.history(session).map { it.name })

            checkNotNull(resolver.openOutputStream(document, "wt")).use { output ->
                apk.inputStream().use { it.copyTo(output) }
            }
            val archive = client.scan(session, document)
            val hash = MessageDigest.getInstance("SHA-256").digest(apk.readBytes())
                .joinToString("") { "%02x".format(it) }
            assertEquals(hash, archive.hash)
            assertEquals(context.packageName, archive.name)
            assertEquals("verified", archive.signature)
            assertTrue(archive.debug)

            val guidance = client.advise(session, installed, true, false)
            assertEquals("rules", guidance.mode)
            assertTrue(guidance.steps.last().first.contains("जाँचें"))

            assertTrue(client.signOut(session).second)
            val restored = client.signIn(checkNotNull(endpoint), email, password, null)
            assertEquals(session.deviceId, restored.deviceId)
            assertEquals(1, client.history(restored).size)
            client.clearHistory(restored)
            assertTrue(client.history(restored).isEmpty())
            assertTrue(client.signOut(restored).second)
        } finally {
            resolver.delete(document, null, null)
            client.forget()
            HttpsURLConnection.setDefaultSSLSocketFactory(previousTls)
        }
    }

    @Test
    fun vpnStartsWithAndroidConsentAndCanStop() {
        assumeTrue(arguments.getString("pilotVpn") == "true")
        val context = instrumentation.targetContext
        capture("pilot-home.png")
        try {
            screen.onNode(hasScrollToIndexAction()).performScrollToNode(hasText("DNS protection"))
            screen.onNodeWithText("DNS protection").performClick()
            screen.onNode(hasScrollToIndexAction()).performScrollToNode(hasText("Enable DNS protection"))
            screen.onNodeWithText("Enable DNS protection").performClick()
            screen.onNodeWithText("Continue to Android consent").performClick()

            val deadline = SystemClock.elapsedRealtime() + 8000
            while (DnsProtectionService.status.value.provider == null && SystemClock.elapsedRealtime() < deadline) {
                val root = instrumentation.uiAutomation.rootInActiveWindow
                if (root?.packageName?.toString() == "com.android.vpndialogs") {
                    val confirm = root.findAccessibilityNodeInfosByText("OK")
                        .firstOrNull { it.isClickable && it.text?.toString() == "OK" }
                    confirm?.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                }
                SystemClock.sleep(150)
            }
            screen.waitUntil(5000) { DnsProtectionService.status.value.provider != null }
            assertEquals(DnsProvider.CLOUDFLARE, DnsProtectionService.status.value.provider)
            screen.onNode(hasScrollToIndexAction()).performScrollToNode(hasText("Stop DNS protection"))
            capture("pilot-dns.png")
            screen.onNodeWithText("Stop DNS protection").performClick()
            screen.waitUntil(5000) { DnsProtectionService.status.value.provider == null }
            assertNull(DnsProtectionService.status.value.provider)
        } finally {
            context.stopService(Intent(context, DnsProtectionService::class.java))
        }
    }

    private fun capture(name: String) {
        screen.waitForIdle()
        val screenshot = checkNotNull(instrumentation.uiAutomation.takeScreenshot())
        File(instrumentation.targetContext.cacheDir, name).outputStream().use {
            screenshot.compress(Bitmap.CompressFormat.PNG, 100, it)
        }
    }
}

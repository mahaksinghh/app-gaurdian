package com.appguardian.privacy

import android.content.ContentValues
import android.os.Build
import android.provider.MediaStore
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class GuardianTest {
    @get:Rule val screen = createAndroidComposeRule<MainActivity>()

    @Test fun recoveryGuideIsUserInitiated() {
        screen.onNodeWithText("Choose APK").assertExists()
        screen.onNodeWithText("Account recovery").performClick()
        screen.onNodeWithText("If you suspect account access", substring = true).assertExists()
    }

    @Test fun permissionWatchPersistsEncryptedDataAndStopsOnRequest() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val installed = checkNotNull(PackageReview(context).installed(context.packageName))
        val watch = PermissionWatch(context)
        try {
            assertTrue(context.packageName in watch.start(installed).packages)
            assertTrue(context.packageName in PermissionWatch(context).restore().packages)
            assertTrue(watch.check().lastCheckedAt != null)
            val persisted = File(context.noBackupFilesDir, "permission-watch.enc").readBytes()
            assertTrue(!persisted.toString(Charsets.UTF_8).contains(context.packageName))
        } finally {
            watch.stop(context.packageName)
        }
        assertTrue(context.packageName !in PermissionWatch(context).restore().packages)
    }

    @Test
    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.Q)
    fun reviewsRealSignedApkAndRejectsInvalidDocument() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val resolver = context.contentResolver
        val installedApk = File(context.applicationInfo.sourceDir).readBytes()
        val entry = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, "appguardian-test.apk")
            put(MediaStore.Downloads.MIME_TYPE, "application/vnd.android.package-archive")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        val item = checkNotNull(resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, entry))
        try {
            checkNotNull(resolver.openOutputStream(item, "wt")).use { it.write(installedApk) }
            val scanner = PackageReview(context)
            val result = scanner.archive(item)
            val installed = checkNotNull(scanner.installed(context.packageName))
            val expectedHash = MessageDigest.getInstance("SHA-256").digest(installedApk)
                .joinToString("") { "%02x".format(it) }
            assertEquals(expectedHash, result.fileSha256)
            assertEquals(context.packageName, result.packageName)
            assertTrue(result.signerSha256.isNotEmpty())
            assertEquals(installed.signerSha256, result.signerSha256)
            assertTrue(result.granted.isEmpty())
            assertTrue(result.findings.any { it.title == "Debuggable build" })

            checkNotNull(resolver.openOutputStream(item, "wt")).use { it.write("Invalid APK".toByteArray()) }
            try {
                scanner.archive(item)
                fail("Invalid document was accepted as an APK")
            } catch (_: IOException) {
                // Expected: Android could not read an APK manifest from this document.
            }
        } finally {
            resolver.delete(item, null, null)
        }
    }
}

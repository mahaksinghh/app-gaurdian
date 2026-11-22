package com.appguardian.privacy

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import java.io.File
import java.io.IOException
import java.security.MessageDigest

internal data class Review(
    val packageName: String,
    val version: String,
    val targetSdk: Int?,
    val fileSha256: String?,
    val signerSha256: List<String>,
    val requested: Set<String>,
    val granted: Set<String>,
    val findings: List<Finding>
)

internal class PackageReview(private val context: Context) {
    private val manager = context.packageManager
    private val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES or
        PackageManager.GET_SERVICES

    @Suppress("DEPRECATION")
    fun archive(uri: Uri): Review {
        if (uri.scheme != "content") throw IOException("Choose a file from the Android file picker.")
        val input = context.contentResolver.openInputStream(uri)
            ?: throw IOException("Android could not open this document.")
        return input.use { source ->
            val copy = File.createTempFile("review-", ".apk", context.cacheDir)
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                copy.outputStream().use { target ->
                    val buffer = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val count = source.read(buffer)
                        if (count < 0) break
                        total += count
                        if (total > MAX_APK_BYTES) throw IOException("Choose an APK up to 100 MiB.")
                        digest.update(buffer, 0, count)
                        target.write(buffer, 0, count)
                    }
                }
                val info = manager.getPackageArchiveInfo(copy.absolutePath, flags)
                    ?: throw IOException("Android could not inspect this APK. It may be invalid or unsupported.")
                info.toReview(digest.digest().hex())
            } finally {
                copy.delete()
            }
        }
    }

    @Suppress("DEPRECATION")
    fun launcherPackages(): List<String> =
        manager.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
            .map { it.activityInfo.packageName }
            .distinct()
            .sorted()

    @Suppress("DEPRECATION")
    fun installed(packageName: String): Review? {
        val info = try {
            manager.getPackageInfo(packageName, flags)
        } catch (_: PackageManager.NameNotFoundException) {
            return null
        }
        return info.toReview(null)
    }

    private fun PackageInfo.toReview(fileHash: String?): Review {
        val requested = requestedPermissions.orEmpty()
        val permissionFlags = requestedPermissionsFlags
        val granted = if (fileHash == null) {
            requested.filterIndexed { index, _ ->
                (permissionFlags?.getOrNull(index) ?: 0) and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
            }.toSet()
        } else {
            emptySet()
        }
        val signers = signingInfo?.apkContentsSigners.orEmpty().map { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).hex()
        }.distinct().sorted()
        val appFlags = applicationInfo?.flags ?: 0
        val hasAccessibilityService = services.orEmpty().any {
            it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
        }
        return Review(
            packageName,
            versionName ?: longVersionCode.toString(),
            applicationInfo?.targetSdkVersion,
            fileHash,
            signers,
            requested.toSet(),
            granted,
            Evidence.review(requested.toSet(), appFlags and ApplicationInfo.FLAG_DEBUGGABLE != 0, hasAccessibilityService)
        )
    }

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    private companion object {
        const val MAX_APK_BYTES = 100L * 1024L * 1024L
    }
}

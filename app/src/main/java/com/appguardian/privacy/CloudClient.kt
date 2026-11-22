package com.appguardian.privacy

import android.content.Context
import android.net.Uri
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.time.Instant
import org.json.JSONArray
import org.json.JSONObject

internal data class CloudProfile(
    val endpoint: String,
    val email: String,
    val deviceId: String,
    val deviceSecret: String,
    val token: String?,
    val expiresAt: Instant?
) {
    fun activeToken(): String? = token?.takeIf { expiresAt?.isAfter(Instant.now()) == true }
}

internal data class CloudHistoryEntry(val name: String, val expiresAt: Instant)

internal data class CloudInspection(
    val name: String,
    val signature: String,
    val debug: Boolean,
    val hash: String,
    val signers: List<String>,
    val permissions: List<String>
)

internal data class GuidedPlan(val mode: String, val scope: String, val steps: List<Pair<String, String>>)

internal class CloudFailure(val code: Int) : IOException("HTTP $code")

internal class CloudClient(private val context: Context) {
    private val store = EncryptedJson(context, "cloud-profile.enc")

    fun profile(): CloudProfile? {
        val saved = store.read()
        if (!saved.has("endpoint")) return null
        return CloudProfile(
            endpoint = saved.getString("endpoint"),
            email = saved.getString("email"),
            deviceId = saved.getString("device"),
            deviceSecret = saved.getString("secret"),
            token = saved.optString("token").takeIf(String::isNotEmpty),
            expiresAt = saved.optString("expires").takeIf(String::isNotEmpty)?.let(Instant::parse)
        )
    }

    fun signIn(url: String, email: String, password: String, enroll: String?): CloudProfile {
        val endpoint = parseEndpoint(url)
        val previous = profile()?.takeIf { it.endpoint == endpoint && it.email.equals(email, ignoreCase = true) }
        val body = JSONObject().put("email", email).put("password", password)
        if (enroll != null) {
            body.put("enrollment_secret", enroll)
        } else if (previous != null) {
            body.put("device_id", previous.deviceId).put("device_secret", previous.deviceSecret)
        }
        val route = if (enroll != null) "register" else "login"
        val reply = JSONObject(send(endpoint, "/v1/auth/$route", "POST", body = body))
        val current = CloudProfile(
            endpoint,
            email,
            reply.getString("device_id"),
            reply.optString("device_secret").takeIf { it.isNotEmpty() } ?: previous?.deviceSecret
                ?: throw IOException("Missing device credential."),
            reply.getString("token"),
            Instant.parse(reply.getString("expires_at"))
        )
        persist(current)
        return current
    }

    fun signOut(current: CloudProfile): Pair<CloudProfile, Boolean> {
        val token = current.activeToken()
        val signedOut = token == null || runCatching {
            send(current.endpoint, "/v1/auth/logout", "POST", token)
        }.isSuccess
        val cleared = current.copy(token = null, expiresAt = null)
        persist(cleared)
        return cleared to signedOut
    }

    fun forget() = store.clear()

    fun history(current: CloudProfile): List<CloudHistoryEntry> {
        val rows = JSONArray(send(current.endpoint, "/v1/scans?limit=10", "GET", requireToken(current)))
        return List(rows.length().coerceAtMost(10)) {
            val entry = rows.getJSONObject(it)
            CloudHistoryEntry(
                entry.getJSONObject("report").getString("package_name"),
                Instant.parse(entry.getString("expires_at"))
            )
        }
    }

    fun clearHistory(current: CloudProfile) {
        send(current.endpoint, "/v1/scans", "DELETE", requireToken(current))
    }

    fun save(current: CloudProfile, review: Review) {
        val report = JSONObject()
            .put("kind", if (review.fileSha256 == null) "installed" else "apk")
            .put("package_name", review.packageName)
            .put("version", review.version)
            .put("apk_sha256", review.fileSha256 ?: JSONObject.NULL)
            .put("signer_sha256", JSONArray(review.signerSha256))
            .put("requested_permissions", JSONArray(review.requested.sorted()))
            .put("granted_permissions", JSONArray(review.granted.sorted()))
        val body = JSONObject().put("report", report).put("consent", JSONObject().put("store_report", true))
        send(current.endpoint, "/v1/scans", "POST", requireToken(current), body)
    }

    fun scan(current: CloudProfile, uri: Uri): CloudInspection {
        if (uri.scheme != "content") throw IOException("Select an Android document.")
        val connection = open(current.endpoint, "/v1/archives/scan", "POST", requireToken(current))
        try {
            connection.doOutput = true
            connection.readTimeout = 75_000
            connection.setRequestProperty("Content-Type", "application/vnd.android.package-archive")
            connection.setRequestProperty("X-AppGuardian-Scan-Consent", "true")
            connection.setChunkedStreamingMode(32 * 1024)
            val input = context.contentResolver.openInputStream(uri) ?: throw IOException("APK is unavailable.")
            input.use { source ->
                connection.outputStream.use { output ->
                    val buffer = ByteArray(32 * 1024)
                    var size = 0
                    while (true) {
                        val count = source.read(buffer)
                        if (count < 0) break
                        if (count > MAX_APK - size) throw CloudFailure(413)
                        output.write(buffer, 0, count)
                        size += count
                    }
                }
            }
            val result = JSONObject(readResponse(connection))
            val report = result.getJSONObject("report")
            return CloudInspection(
                report.getString("package_name"),
                result.getString("signature"),
                result.getBoolean("debuggable"),
                report.getString("apk_sha256"),
                report.getJSONArray("signer_sha256").strings().take(16),
                report.getJSONArray("requested_permissions").strings().take(256)
            )
        } finally {
            connection.disconnect()
        }
    }

    fun advise(current: CloudProfile, review: Review?, hindi: Boolean, useAi: Boolean): GuidedPlan {
        val body = JSONObject()
            .put("scenario", when {
                review == null -> "account-incident"
                review.fileSha256 != null -> "before-install"
                else -> "installed-app"
            })
            .put("language", if (hindi) "hi" else "en")
            .put("use_ai", useAi)
            .put("evidence", JSONArray(review?.let(::evidenceCodes).orEmpty()))
        val reply = JSONObject(send(current.endpoint, "/v1/guide", "POST", requireToken(current), body))
        val steps = reply.getJSONArray("steps")
        return GuidedPlan(
            reply.getString("mode"),
            reply.getString("scope"),
            List(steps.length().coerceAtMost(12)) {
                val step = steps.getJSONObject(it)
                step.getString("title") to step.getString("instruction")
            }
        )
    }

    private fun persist(current: CloudProfile) {
        store.update {
            JSONObject().put("endpoint", current.endpoint).put("email", current.email)
                .put("device", current.deviceId).put("secret", current.deviceSecret)
                .put("token", current.token.orEmpty()).put("expires", current.expiresAt?.toString().orEmpty())
        }
    }

    private fun send(
        endpoint: String,
        route: String,
        method: String,
        token: String? = null,
        body: JSONObject? = null
    ): String {
        val connection = open(endpoint, route, method, token)
        try {
            body?.let {
                val bytes = it.toString().toByteArray()
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setFixedLengthStreamingMode(bytes.size)
                connection.outputStream.use { output -> output.write(bytes) }
            }
            return readResponse(connection)
        } finally {
            connection.disconnect()
        }
    }

    private fun open(endpoint: String, route: String, method: String, token: String?): HttpURLConnection =
        (URI.create(endpoint + route).toURL().openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = false
            requestMethod = method
            connectTimeout = 8000
            readTimeout = 12_000
            useCaches = false
            setRequestProperty("Accept", "application/json")
            if (token != null) setRequestProperty("Authorization", "Bearer $token")
        }

    private fun readResponse(connection: HttpURLConnection): String {
        val status = connection.responseCode
        if (status !in 200..299) throw CloudFailure(status)
        if (status == 204) return ""
        return connection.inputStream.use { input ->
            val buffer = ByteArray(8192)
            val response = ByteArrayOutputStream()
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count > MAX_RESPONSE - response.size()) throw IOException("Response too large.")
                response.write(buffer, 0, count)
            }
            response.toString(Charsets.UTF_8.name())
        }
    }

    private fun requireToken(current: CloudProfile): String = current.activeToken() ?: throw CloudFailure(401)

    private companion object {
        const val MAX_APK = 25 * 1024 * 1024
        const val MAX_RESPONSE = 2 * 1024 * 1024
    }
}

internal fun parseEndpoint(value: String): String {
    val uri = URI.create(value.trim())
    require(uri.scheme == "https" && uri.host != null && uri.rawUserInfo == null &&
        uri.rawFragment == null && uri.rawQuery == null && uri.port in -1..65535
    ) { "Enter a valid HTTPS server address." }
    return uri.toString().trimEnd('/')
}

private fun evidenceCodes(report: Review): List<String> = buildList {
    val permissions = report.requested
    fun has(name: String) = "android.permission.$name" in permissions
    if (has("READ_SMS") || has("RECEIVE_SMS")) add("sms")
    if (has("READ_CONTACTS")) add("contacts")
    if (has("CAMERA")) add("camera")
    if (has("RECORD_AUDIO")) add("microphone")
    if (has("ACCESS_FINE_LOCATION") || has("ACCESS_BACKGROUND_LOCATION")) add("location")
    if (has("REQUEST_INSTALL_PACKAGES")) add("package-installer")
    val findings = report.findings.map { it.title }.toSet()
    if ("Accessibility service" in findings) add("accessibility")
    if ("Debuggable build" in findings) add("debuggable")
    if ("Cleartext traffic opt-in" in findings) add("cleartext")
}

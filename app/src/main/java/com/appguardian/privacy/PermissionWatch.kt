package com.appguardian.privacy

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.io.IOException
import java.security.GeneralSecurityException
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

internal data class WatchEvent(
    val packageName: String,
    val checkedAt: Long,
    val changes: List<String>
)

internal data class WatchSummary(
    val packages: List<String> = emptyList(),
    val lastCheckedAt: Long? = null,
    val events: List<WatchEvent> = emptyList()
)

internal class PermissionWatch(context: Context) {
    private val app = context.applicationContext
    private val store = EncryptedJson(app, "permission-watch.enc")

    fun restore(): WatchSummary = summary(store.read()).also {
        if (it.packages.isNotEmpty()) schedule()
    }

    fun start(review: Review): WatchSummary {
        require(review.fileSha256 == null)
        val next = store.update { state ->
            val packages = packages(state)
            if (!packages.has(review.packageName)) {
                if (packages.length() >= MAX_PACKAGES) throw IOException("Permission watch is full.")
                packages.put(review.packageName, snapshot(review, UUID.randomUUID().toString()))
            }
            state.put("packages", packages)
        }
        schedule()
        return summary(next)
    }

    fun stop(packageName: String): WatchSummary {
        val next = store.update { state ->
            val packages = packages(state)
            packages.remove(packageName)
            val remaining = recentEvents(state, System.currentTimeMillis()).filter {
                it.getString("package") != packageName
            }
            state.put("packages", packages).put("events", JSONArray(remaining))
        }
        val result = summary(next)
        if (result.packages.isEmpty()) WorkManager.getInstance(app).cancelUniqueWork(WORK_NAME)
        return result
    }

    fun check(): WatchSummary = synchronized(checkLock) {
        val before = packages(store.read())
        if (before.length() == 0) return@synchronized WatchSummary()
        val scanner = PackageReview(app)
        val observed = before.keys().asSequence().associateWith { scanner.installed(it) }
        val now = System.currentTimeMillis()
        val next = store.update { state ->
            val current = packages(state)
            if (current.length() == 0) return@update state
            val events = recentEvents(state, now).toMutableList()
            observed.forEach { (packageName, review) ->
                val previous = current.optJSONObject(packageName) ?: return@forEach
                val generation = previous.getString("generation")
                if (before.getJSONObject(packageName).getString("generation") != generation) return@forEach
                val changes = compare(previous, review)
                if (changes.isNotEmpty()) {
                    events.add(JSONObject().put("package", packageName).put("at", now)
                        .put("changes", JSONArray(changes)))
                }
                if (review == null) {
                    previous.put("visible", false)
                } else {
                    current.put(packageName, snapshot(review, generation))
                }
            }
            state.put("packages", current).put("events", JSONArray(events.takeLast(MAX_EVENTS)))
                .put("lastCheckedAt", now)
        }
        summary(next)
    }

    private fun compare(previous: JSONObject, current: Review?): List<String> {
        val visible = previous.optBoolean("visible", true)
        if (current == null) return if (visible) listOf("The package is no longer visible to AppGuardian.") else emptyList()
        if (previous.getJSONArray("signers").strings().toSet() != current.signerSha256.toSet()) {
            return listOf("The signing certificates changed. Permission comparison has a new baseline.")
        }
        return buildList {
            if (!visible) add("The package is visible to AppGuardian again.")
            if (previous.getString("version") != current.version) add("The app version changed.")
            addAll(Evidence.changedGrants(previous.getJSONArray("grants").strings().toSet(), current.granted))
        }
    }

    private fun summary(state: JSONObject): WatchSummary =
        WatchSummary(
            packages(state).keys().asSequence().sorted().toList(),
            state.optLong("lastCheckedAt").takeIf { it > 0 },
            recentEvents(state, System.currentTimeMillis()).asReversed().map { event ->
                WatchEvent(event.getString("package"), event.getLong("at"), event.getJSONArray("changes").strings())
            }
        )

    private fun packages(state: JSONObject) = state.optJSONObject("packages") ?: JSONObject()

    private fun snapshot(review: Review, generation: String) =
        JSONObject().put("visible", true).put("generation", generation).put("version", review.version)
            .put("signers", JSONArray(review.signerSha256)).put("grants", JSONArray(review.granted.sorted()))

    private fun recentEvents(state: JSONObject, now: Long): List<JSONObject> {
        val events = state.optJSONArray("events") ?: return emptyList()
        return (0 until events.length()).map(events::getJSONObject).filter {
            it.getLong("at") >= now - TimeUnit.DAYS.toMillis(14)
        }
    }

    private fun schedule() {
        val work = PeriodicWorkRequestBuilder<PermissionWatchWorker>(15, TimeUnit.MINUTES).build()
        WorkManager.getInstance(app).enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, work)
    }

    private companion object {
        val checkLock = Any()
        const val WORK_NAME = "appguardian.permission-watch"
        const val MAX_PACKAGES = 25
        const val MAX_EVENTS = 100
    }
}

internal fun JSONArray.strings(): List<String> = List(length(), ::getString)

class PermissionWatchWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            PermissionWatch(applicationContext).check()
            Result.success()
        } catch (_: IOException) {
            Result.retry()
        } catch (_: GeneralSecurityException) {
            Result.failure()
        } catch (_: JSONException) {
            Result.failure()
        }
    }
}

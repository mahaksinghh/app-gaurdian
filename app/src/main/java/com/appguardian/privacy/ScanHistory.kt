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

internal data class SavedReview(val id: String, val savedAt: Long, val review: Review)

internal class ScanHistory(context: Context) {
    private val app = context.applicationContext
    private val store = EncryptedJson(app, "scan-history.enc")

    fun save(review: Review): SavedReview {
        val now = System.currentTimeMillis()
        val item = SavedReview(UUID.randomUUID().toString(), now, review)
        store.update { old ->
            val reports = (listOf(item.toJson()) + recent(old, now)).take(MAX_REPORTS)
            JSONObject().put("reports", JSONArray(reports))
        }
        val work = PeriodicWorkRequestBuilder<ScanHistoryWorker>(1, TimeUnit.DAYS).build()
        WorkManager.getInstance(app).enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, work)
        return item
    }

    fun load(): List<SavedReview> {
        val old = store.read()
        val now = System.currentTimeMillis()
        val records = recent(old, now)
        if (records.size == old.optJSONArray("reports")?.length() || !old.has("reports")) {
            return records.map(::readRecord)
        }
        val pruned = store.update { JSONObject().put("reports", JSONArray(recent(it, now))) }
        return recent(pruned, now).map(::readRecord)
    }

    fun delete(id: String): List<SavedReview> {
        val now = System.currentTimeMillis()
        val updated = store.update { old ->
            val reports = recent(old, now).filter { it.getString("id") != id }
            JSONObject().put("reports", JSONArray(reports))
        }
        return recent(updated, now).map(::readRecord)
    }

    fun clear() {
        store.clear()
        WorkManager.getInstance(app).cancelUniqueWork(WORK_NAME)
    }

    private fun recent(state: JSONObject, now: Long): List<JSONObject> {
        val items = state.optJSONArray("reports") ?: return emptyList()
        val minDate = now - TimeUnit.DAYS.toMillis(7)
        return (0 until items.length()).map(items::getJSONObject).filter { it.getLong("savedAt") >= minDate }
    }

    private fun SavedReview.toJson() = JSONObject().put("id", id).put("savedAt", savedAt)
        .put("name", review.packageName).put("version", review.version)
        .put("target", review.targetSdk ?: JSONObject.NULL)
        .put("file", review.fileSha256 ?: JSONObject.NULL)
        .put("signers", JSONArray(review.signerSha256))
        .put("requested", JSONArray(review.requested.sorted()))
        .put("granted", JSONArray(review.granted.sorted()))
        .put("findings", JSONArray(review.findings.map {
            JSONObject().put("title", it.title).put("explanation", it.explanation)
        }))

    private fun readRecord(entry: JSONObject): SavedReview {
        val findings = entry.getJSONArray("findings")
        val report = Review(
            packageName = entry.getString("name"),
            version = entry.getString("version"),
            targetSdk = if (entry.isNull("target")) null else entry.getInt("target"),
            fileSha256 = if (entry.isNull("file")) null else entry.getString("file"),
            signerSha256 = entry.getJSONArray("signers").strings(),
            requested = entry.getJSONArray("requested").strings().toSet(),
            granted = entry.getJSONArray("granted").strings().toSet(),
            findings = List(findings.length()) {
                val finding = findings.getJSONObject(it)
                Finding(finding.getString("title"), finding.getString("explanation"))
            }
        )
        return SavedReview(entry.getString("id"), entry.getLong("savedAt"), report)
    }

    private companion object {
        const val WORK_NAME = "appguardian.history-retention"
        const val MAX_REPORTS = 30
    }
}

class ScanHistoryWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            ScanHistory(applicationContext).load()
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

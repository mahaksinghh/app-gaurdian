package com.appguardian.privacy

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
internal fun ReviewSummary(
    report: Review,
    saved: Boolean,
    busy: Boolean,
    feedback: String,
    openSettings: () -> Unit,
    recheck: () -> Unit,
    readCurrent: () -> Unit
) {
    val archive = report.fileSha256 != null
    ElevatedCard(Modifier.fillMaxWidth().animateContentSize()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(
                when {
                    saved -> "Saved review"
                    archive -> "Before you install"
                    else -> "Review this app’s access"
                },
                style = MaterialTheme.typography.headlineSmall
            )
            Text(report.packageName, style = MaterialTheme.typography.titleMedium)
            val first = report.findings.firstOrNull()
            if (first != null) {
                Text(first.title, style = MaterialTheme.typography.titleSmall)
                Text(first.explanation)
            } else {
                Text("This review found no matching indicators. Check the app’s source and whether its permissions fit what you use it for.")
            }
            Text("What to do next", style = MaterialTheme.typography.titleMedium)
            when {
                archive -> Text("Keep the file uninstalled if the source or permissions are unexpected. Use the fingerprint comparison below when the publisher provides a value.")
                saved -> {
                    Text("Check the app again before acting on permissions shown in this saved report.")
                    OutlinedButton(enabled = !busy, onClick = readCurrent) { Text("Check this app now") }
                }
                else -> {
                    Text("Compare the granted permissions with what you use the app for. Change access in Android Settings and return here to check the result.")
                    Button(enabled = !busy, onClick = openSettings) { Text("Open app settings") }
                    OutlinedButton(enabled = !busy, onClick = recheck) { Text("Recheck permissions") }
                }
            }
            if (feedback.isNotBlank()) {
                Text(feedback, color = MaterialTheme.colorScheme.primary)
            }
        }
    }
}

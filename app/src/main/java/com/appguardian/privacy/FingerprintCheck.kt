package com.appguardian.privacy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.util.Locale

internal fun normalizeFingerprint(text: String): String? {
    if (text.length > 256) return null
    val compact = text.filterNot { it == ':' || it.isWhitespace() }.lowercase(Locale.ROOT)
    return compact.takeIf { it.length == 64 && it.all { char -> char in 'a'..'f' || char in '0'..'9' } }
}

@Composable
internal fun FingerprintCheck(apkSha256: String, signers: List<String>) {
    var typed by remember(apkSha256) { mutableStateOf("") }
    var certificate by remember(apkSha256) { mutableStateOf(false) }
    var outcome by remember(apkSha256) { mutableStateOf("") }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Compare a SHA-256 from your publisher’s trusted site.", style = MaterialTheme.typography.bodyMedium)
        if (signers.isNotEmpty()) {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                FilterChip(selected = !certificate, onClick = {
                    certificate = false
                    outcome = ""
                },
                    label = { Text("APK hash") })
                FilterChip(selected = certificate, onClick = {
                    certificate = true
                    outcome = ""
                },
                    label = { Text("Signing fingerprint") })
            }
        }
        OutlinedTextField(
            value = typed,
            onValueChange = {
                if (it.length <= 256) typed = it
                outcome = ""
            },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Publisher’s expected SHA-256") },
            singleLine = true
        )
        OutlinedButton(enabled = typed.isNotBlank(), onClick = {
            val given = normalizeFingerprint(typed)
            outcome = when {
                given == null -> "Enter 64 hexadecimal characters. Spaces and colons are accepted."
                (if (certificate) given in signers else given == apkSha256) -> "The values match. Confirm the publisher independently."
                else -> "The values differ. Recheck the source before installing."
            }
        }) { Text("Compare fingerprints") }
        if (outcome.isNotEmpty()) Text(outcome, color = MaterialTheme.colorScheme.primary)
    }
}

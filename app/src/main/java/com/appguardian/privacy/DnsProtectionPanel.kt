package com.appguardian.privacy

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.unit.dp

@Composable
internal fun DnsProtectionPanel(start: (DnsProvider, String) -> Unit, stop: () -> Unit) {
    var rules by rememberSaveable { mutableStateOf("") }
    var providerName by rememberSaveable { mutableStateOf(DnsProvider.CLOUDFLARE.name) }
    var error by rememberSaveable { mutableStateOf<String?>(null) }
    var confirming by rememberSaveable { mutableStateOf(false) }
    val provider = DnsProvider.valueOf(providerName)
    val status by DnsProtectionService.status.collectAsState()
    val active = status.provider != null

    ElevatedCard {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("DNS protection", style = MaterialTheme.typography.headlineSmall)
            Text("Block domains you choose when apps use the Android DNS route. Apps using their own DNS or direct IP connections can bypass these rules.")
            status.note?.let { Text(it) }
            AnimatedVisibility(active) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("On · ${status.provider?.label.orEmpty()} DNS over HTTPS", style = MaterialTheme.typography.titleMedium)
                    Text("${status.blocked} blocked · ${status.failed} DNS requests failed")
                    OutlinedButton(onClick = stop) { Text("Stop DNS protection") }
                }
            }
            AnimatedVisibility(!active) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("DNS provider", style = MaterialTheme.typography.titleSmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        DnsProvider.entries.forEach { option ->
                            FilterChip(
                                selected = option == provider,
                                onClick = { providerName = option.name },
                                label = { Text(option.label) }
                            )
                        }
                    }
                    OutlinedTextField(
                        value = rules,
                        onValueChange = { if (it.length <= 8192) rules = it },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Domains to block") },
                        supportingText = { Text(error ?: "One domain per line. Subdomains are included.") },
                        isError = error != null,
                        minLines = 2,
                        maxLines = 5
                    )
                    Button(onClick = {
                        error = try {
                            DomainRules.parse(rules)
                            confirming = true
                            null
                        } catch (_: IllegalArgumentException) {
                            "Enter up to 100 domain names, without paths, ports or wildcards."
                        }
                    }) { Text("Enable DNS protection") }
                }
            }
        }
    }

    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("Allow DNS protection?") },
            text = {
                Text(
                    "${provider.label} can see the allowed DNS names and your connection’s public IP. Requests use HTTPS. " +
                        "AppGuardian keeps counters in memory. Android will ask for VPN permission. " +
                        "Starting can replace another active VPN on this profile."
                )
            },
            confirmButton = {
                Button(onClick = {
                    confirming = false
                    start(provider, rules)
                }) { Text("Continue to Android consent") }
            },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text("Cancel") } }
        )
    }
}

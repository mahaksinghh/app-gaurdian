package com.appguardian.privacy

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private val scanner by lazy { PackageReview(applicationContext) }
    private var review by mutableStateOf<Review?>(null)
    private var busy by mutableStateOf(false)
    private var status by mutableStateOf("")
    private var showApps by mutableStateOf(false)
    private var apps by mutableStateOf(emptyList<String>())
    private var awaitingSettings by mutableStateOf(false)
    private var baseline: Review? = null

    private val picker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) runReview {
            scanner.archive(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF99F4CF),
                    onPrimary = Color(0xFF003828),
                    background = Color(0xFF0D1918),
                    surface = Color(0xFF142523),
                    surfaceVariant = Color(0xFF203633)
                )
            ) {
                GuardianScreen()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (awaitingSettings) {
            awaitingSettings = false
            verify()
        }
    }

    private fun runReview(load: () -> Review?) = runTask {
        review = null
        baseline = null
        showApps = false
        val result = withContext(Dispatchers.IO) { load() }
        review = result
        baseline = result?.takeIf { it.fileSha256 == null }
        status = if (result == null) "Android could no longer read this app." else ""
    }

    private fun runTask(action: suspend () -> Unit) {
        if (busy) return
        busy = true
        status = ""
        lifecycleScope.launch {
            try {
                action()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                status = "Android could not finish the review. Choose an accessible APK up to 100 MiB, or try reviewing the app again."
            } finally {
                busy = false
            }
        }
    }

    private fun listApps() = runTask {
        apps = withContext(Dispatchers.IO) { scanner.launcherPackages() }
        showApps = true
    }

    private fun verify() {
        val previous = baseline ?: return
        runTask {
            val current = withContext(Dispatchers.IO) { scanner.installed(previous.packageName) }
            review = current
            if (current == null) {
                baseline = null
                status = "Android no longer exposes this package to AppGuardian. Check your launcher or Android Settings to confirm removal."
            } else {
                status = if (
                    previous.version != current.version ||
                    previous.signerSha256 != current.signerSha256
                ) {
                    "The app version or signing details changed. Review the updated evidence below."
                } else {
                    Evidence.changedGrants(previous.granted, current.granted).joinToString("\n")
                        .ifBlank { "No permission grant changes were visible to AppGuardian." }
                }
                baseline = current
            }
        }
    }

    private fun launchSystemAction(intent: Intent, verifyOnReturn: Boolean = false) {
        try {
            startActivity(intent)
            awaitingSettings = verifyOnReturn
        } catch (_: ActivityNotFoundException) {
            status = "This device does not expose that screen. Open Android Settings to continue."
        } catch (_: SecurityException) {
            status = "Android blocked that action. Open Android Settings to continue."
        }
    }

    @Composable
    private fun GuardianScreen() {
        var recovery by remember { mutableStateOf(false) }
        Scaffold { insets ->
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(insets),
                contentPadding = PaddingValues(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                item {
                    Text("AppGuardian", style = MaterialTheme.typography.headlineLarge)
                    Text("Review an APK before installing it, or check the permissions of an app on your phone.")
                }
                item {
                    ElevatedCard {
                        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text("APK review", style = MaterialTheme.typography.titleLarge)
                            Text("Choose one APK to scan on this device. AppGuardian does not upload or install it.")
                            Button(enabled = !busy, onClick = { picker.launch("*/*") }) { Text("Choose APK") }
                        }
                    }
                }
                item {
                    OutlinedButton(enabled = !busy, onClick = { listApps() }) { Text("Review installed apps") }
                    if (showApps) {
                        Text("Android shows AppGuardian a limited list of apps with launcher entries.")
                        if (apps.isEmpty()) Text("No launcher apps are visible.")
                    }
                }
                if (showApps) {
                    items(apps, key = { it }) { name ->
                        TextButton(enabled = !busy, onClick = { runReview { scanner.installed(name) } }) { Text(name) }
                    }
                }
                item {
                    AnimatedVisibility(busy) { LinearProgressIndicator(Modifier.fillMaxWidth()) }
                    AnimatedVisibility(status.isNotBlank()) { Text(status) }
                }
                review?.let { result ->
                    item {
                        Text(result.packageName, style = MaterialTheme.typography.headlineSmall)
                        Text("Version ${result.version} · Target Android API ${result.targetSdk ?: "unknown"}")
                        Text("These findings describe observable capabilities. A scan cannot determine everything an app may do after installation.")
                    }
                    items(result.findings) { finding ->
                        ElevatedCard {
                            Column(Modifier.padding(16.dp)) {
                                Text(finding.title, style = MaterialTheme.typography.titleMedium)
                                Text(finding.explanation)
                            }
                        }
                    }
                    item {
                        if (result.findings.isEmpty()) Text("No indicators matched the checks in this version.")
                        result.fileSha256?.let {
                            Text("APK SHA-256")
                            Hash(it)
                        }
                        Text("Current signing certificate SHA-256")
                        if (result.signerSha256.isEmpty()) Text("Android returned no signing certificate.")
                        result.signerSha256.forEach { Hash(it) }
                        Text("Requested permissions", style = MaterialTheme.typography.titleMedium)
                        if (result.requested.isEmpty()) Text("None reported by Android.")
                        result.requested.sorted().forEach {
                            Text(if (result.fileSha256 == null) "${if (it in result.granted) "Granted" else "Not granted"} · $it" else it)
                        }
                    }
                    item {
                        Text("Protect and verify", style = MaterialTheme.typography.titleLarge)
                        if (result.fileSha256 != null) {
                            Text("Leave the APK uninstalled if its source or permissions are unexpected. Compare the hash or signing certificate with a value published by the developer through a trusted channel.")
                        } else {
                            Text("Use Android Settings to review or revoke permissions. To remove an app, use the Uninstall control there if Android offers it.")
                            Button(enabled = !busy, onClick = {
                                launchSystemAction(
                                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", result.packageName, null)),
                                    verifyOnReturn = true
                                )
                            }) { Text("Open app settings") }
                            OutlinedButton(enabled = !busy, onClick = { verify() }) { Text("Recheck permissions") }
                        }
                    }
                }
                item {
                    TextButton(onClick = { recovery = !recovery }) { Text(if (recovery) "Hide account recovery" else "Account recovery") }
                    AnimatedVisibility(recovery) {
                        Text(
                            "If you suspect account access, use a trusted device. Open the provider’s official app or website, change your password, sign out unknown sessions, review recovery details and enable multifactor authentication. Reopen the provider’s security page to verify the changes."
                        )
                    }
                }
            }
        }
    }

    @Composable
    private fun Hash(value: String) {
        Text(value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
    }
}

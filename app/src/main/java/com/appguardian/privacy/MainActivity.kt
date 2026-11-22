package com.appguardian.privacy

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import java.text.DateFormat
import java.util.Date
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
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
    private val watch by lazy { PermissionWatch(applicationContext) }
    private val history by lazy { ScanHistory(applicationContext) }
    private var savedReviews by mutableStateOf(emptyList<SavedReview>())
    private var showHistory by mutableStateOf(false)
    private var showNetwork by mutableStateOf(false)
    private var showCloud by mutableStateOf(false)
    private var pendingDnsStart: Intent? = null
    private var viewingSaved by mutableStateOf(false)
    private var savedCurrent by mutableStateOf(false)
    private var watchSummary by mutableStateOf(WatchSummary())
    private var showWatch by mutableStateOf(false)
    private var review by mutableStateOf<Review?>(null)
    private var busy by mutableStateOf(false)
    private var scanningApk by mutableStateOf(false)
    private var status by mutableStateOf("")
    private var showApps by mutableStateOf(false)
    private var apps by mutableStateOf(emptyList<String>())
    private var awaitingSettings by mutableStateOf(false)
    private var baseline: Review? = null

    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val serviceIntent = pendingDnsStart
        pendingDnsStart = null
        if (result.resultCode == RESULT_OK && serviceIntent != null) startDnsService(serviceIntent)
    }

    private val picker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null && !busy) {
            scanningApk = true
            runReview { scanner.archive(uri) }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF99F4CF),
                    onPrimary = Color(0xFF003828),
                    background = Color(0xFF0D1918),
                    surface = Color(0xFF142523),
                    surfaceVariant = Color(0xFF203633),
                    surfaceContainer = Color(0xFF192C28),
                    surfaceContainerHigh = Color(0xFF233732),
                    surfaceContainerHighest = Color(0xFF29403A),
                    onBackground = Color(0xFFE6F1EC),
                    onSurface = Color(0xFFE6F1EC),
                    onSurfaceVariant = Color(0xFFB7CAC2),
                    outline = Color(0xFF79928A)
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
        showWatch = false
        showHistory = false
        showNetwork = false
        showCloud = false
        viewingSaved = false
        savedCurrent = false
        val result = withContext(Dispatchers.IO) { load() }
        review = result
        baseline = result?.takeIf { it.fileSha256 == null }
        if (baseline != null) {
            watchSummary = withContext(Dispatchers.IO) { watch.restore() }
        }
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
                scanningApk = false
            }
        }
    }

    private fun openNetwork() {
        if (busy) return
        showNetwork = true
        showCloud = false
        showApps = false
        showWatch = false
        showHistory = false
        review = null
        baseline = null
        status = ""
    }

    private fun openCloud() {
        if (busy) return
        showCloud = true
        showNetwork = false
        showApps = false
        showWatch = false
        showHistory = false
        status = ""
    }

    private fun requestVpn(provider: DnsProvider, rules: String) {
        val serviceIntent = Intent(this, DnsProtectionService::class.java).setAction(DnsProtectionService.START)
            .putExtra(DnsProtectionService.PROVIDER, provider.name)
            .putExtra(DnsProtectionService.RULES, rules)
        try {
            val consent = VpnService.prepare(this)
            if (consent == null) {
                startDnsService(serviceIntent)
            } else {
                pendingDnsStart = serviceIntent
                vpnConsent.launch(consent)
            }
        } catch (_: ActivityNotFoundException) {
            status = "Android VPN consent is unavailable on this device."
        } catch (_: SecurityException) {
            status = "Android blocked DNS protection on this profile."
        }
    }

    private fun startDnsService(intent: Intent) {
        try {
            startForegroundService(intent)
        } catch (_: IllegalStateException) {
            status = "Open AppGuardian again and retry DNS protection."
        } catch (_: SecurityException) {
            status = "Android blocked DNS protection on this profile."
        }
    }

    private fun stopDnsService() {
        stopService(Intent(this, DnsProtectionService::class.java))
    }

    private fun listApps() = runTask {
        apps = withContext(Dispatchers.IO) { scanner.launcherPackages() }
        showApps = true
        showWatch = false
        showHistory = false
        showNetwork = false
        showCloud = false
        review = null
        baseline = null
    }

    private fun openWatch() = runTask {
        watchSummary = withContext(Dispatchers.IO) { watch.restore() }
        showWatch = true
        showApps = false
        showHistory = false
        showNetwork = false
        showCloud = false
        review = null
        baseline = null
    }

    private fun toggleWatch(result: Review) = runTask {
        watchSummary = withContext(Dispatchers.IO) {
            val current = watch.restore()
            if (result.packageName in current.packages) watch.stop(result.packageName) else watch.start(result)
        }
        val enabled = result.packageName in watchSummary.packages
        status = if (enabled) "Permission monitoring enabled for this app." else "Permission monitoring stopped for this app."
    }

    private fun removeWatch(packageName: String) = runTask {
        watchSummary = withContext(Dispatchers.IO) { watch.stop(packageName) }
    }

    private fun checkWatch() = runTask {
        watchSummary = withContext(Dispatchers.IO) { watch.check() }
        status = "Permission check finished for watched apps that Android exposes."
    }

    private fun openHistory() = runTask {
        savedReviews = withContext(Dispatchers.IO) { history.load() }
        showHistory = true
        showNetwork = false
        showCloud = false
        showApps = false
        showWatch = false
        review = null
        baseline = null
    }

    private fun openSaved(saved: SavedReview) {
        if (busy) return
        showHistory = false
        review = saved.review
        baseline = null
        viewingSaved = true
        status = "Snapshot saved " + date(saved.savedAt)
    }

    private fun saveReport(snapshot: Review) = runTask {
        withContext(Dispatchers.IO) { history.save(snapshot) }
        savedCurrent = true
        status = "Report saved on this device for up to 7 days."
    }

    private fun deleteSaved(id: String) = runTask {
        savedReviews = withContext(Dispatchers.IO) { history.delete(id) }
    }

    private fun clearHistory() = runTask {
        withContext(Dispatchers.IO) { history.clear() }
        savedReviews = emptyList()
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
        var confirmClear by remember { mutableStateOf(false) }
        if (confirmClear) {
            AlertDialog(
                onDismissRequest = { confirmClear = false },
                title = { Text("Clear scan history?") },
                text = { Text("All saved reports on this device will be deleted.") },
                confirmButton = {
                    TextButton(onClick = {
                        confirmClear = false
                        clearHistory()
                    }) { Text("Clear history") }
                },
                dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("Cancel") } }
            )
        }
        Scaffold { insets ->
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(insets),
                contentPadding = PaddingValues(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                item { GuardianHeader() }
                item { ApkEntryCard(scanningApk, !busy) { picker.launch("*/*") } }
                item {
                    OutlinedButton(enabled = !busy, onClick = { listApps() }) { Text("Review installed apps") }
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        TextButton(enabled = !busy, onClick = { openWatch() }) { Text("Permission monitor") }
                        TextButton(enabled = !busy, onClick = { openHistory() }) { Text("Scan history") }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        TextButton(enabled = !busy, onClick = { openNetwork() }) { Text("DNS protection") }
                        TextButton(enabled = !busy, onClick = { openCloud() }) { Text("Cloud account") }
                    }
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
                if (showNetwork) { item { DnsProtectionPanel(::requestVpn, ::stopDnsService) } }
                if (showCloud) { item { CloudPanel(review) } }
                if (showWatch) {
                    item {
                        Text("Permission monitor", style = MaterialTheme.typography.headlineSmall)
                        Text("Choose apps from Installed Apps to watch. Android schedules checks and can delay them. Only visible apps can be monitored.")
                        watchSummary.lastCheckedAt?.let { Text("Last check: ${date(it)}") }
                        if (watchSummary.packages.isEmpty()) Text("No apps are being monitored.")
                        OutlinedButton(enabled = !busy && watchSummary.packages.isNotEmpty(), onClick = { checkWatch() }) {
                            Text("Check watched apps")
                        }
                    }
                    items(watchSummary.packages, key = { "watch:$it" }) { packageName ->
                        ElevatedCard {
                            Column(Modifier.padding(16.dp)) {
                                Text(packageName, style = MaterialTheme.typography.titleMedium)
                                TextButton(enabled = !busy, onClick = { removeWatch(packageName) }) {
                                    Text("Stop monitoring")
                                }
                            }
                        }
                    }
                    if (watchSummary.events.isEmpty() && watchSummary.packages.isNotEmpty()) {
                        item { Text("No recorded changes in the last 14 days.") }
                    }
                    items(watchSummary.events) { event ->
                        Column {
                            Text(event.packageName, style = MaterialTheme.typography.titleMedium)
                            Text(date(event.checkedAt), style = MaterialTheme.typography.bodySmall)
                            event.changes.forEach { Text(it) }
                        }
                    }
                }
                if (showHistory) {
                    item {
                        Text("Scan history", style = MaterialTheme.typography.headlineSmall)
                        Text("Reports you save stay encrypted on this device for up to 7 days.")
                        if (savedReviews.isEmpty()) {
                            Text("No saved reports.")
                        } else {
                            TextButton(enabled = !busy, onClick = { confirmClear = true }) { Text("Clear history") }
                        }
                    }
                    items(savedReviews, key = { it.id }) { saved ->
                        ElevatedCard {
                            Column(Modifier.padding(16.dp)) {
                                Text(saved.review.packageName, style = MaterialTheme.typography.titleMedium)
                                Text(date(saved.savedAt), style = MaterialTheme.typography.bodySmall)
                                Row {
                                    TextButton(enabled = !busy, onClick = { openSaved(saved) }) { Text("View report") }
                                    TextButton(enabled = !busy, onClick = { deleteSaved(saved.id) }) { Text("Delete report") }
                                }
                            }
                        }
                    }
                }
                review?.takeUnless { showCloud }?.let { result ->
                    item {
                        if (viewingSaved) Text("Saved report", style = MaterialTheme.typography.labelLarge)
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
                        } else if (viewingSaved) {
                            Text("Review the installed app again to check its current permissions.")
                            OutlinedButton(enabled = !busy, onClick = { runReview { scanner.installed(result.packageName) } }) {
                                Text("Check this app now")
                            }
                        } else {
                            Text("Use Android Settings to review or revoke permissions. To remove an app, use the Uninstall control there if Android offers it.")
                            Button(enabled = !busy, onClick = {
                                launchSystemAction(
                                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", result.packageName, null)),
                                    verifyOnReturn = true
                                )
                            }) { Text("Open app settings") }
                            OutlinedButton(enabled = !busy, onClick = { verify() }) { Text("Recheck permissions") }
                            HorizontalDivider(Modifier.padding(vertical = 12.dp))
                            Text(
                                "Watch this app for permission changes. AppGuardian checks periodically when Android allows it and keeps up to 14 days of changes on this device."
                            )
                            TextButton(enabled = !busy, onClick = { toggleWatch(result) }) {
                                Text(if (result.packageName in watchSummary.packages) "Stop monitoring" else "Watch permission changes")
                            }
                        }
                        if (!viewingSaved) {
                            TextButton(enabled = !busy && !savedCurrent, onClick = { saveReport(result) }) {
                                Text(if (savedCurrent) "Saved on this device" else "Save report on this device")
                            }
                        }
                    }
                }
                item {
                    TextButton(onClick = { recovery = !recovery }) { Text(if (recovery) "Hide account recovery" else "Account recovery") }
                    AnimatedVisibility(recovery) {
                        RecoveryGuide { url -> launchSystemAction(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
                    }
                }
            }
        }
    }

    private fun date(value: Long): String = DateFormat.getDateTimeInstance().format(Date(value))

    @Composable
    private fun Hash(value: String) {
        Text(value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
    }
}

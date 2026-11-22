package com.appguardian.privacy

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

private enum class ConsentAction(val title: String, val text: String) {
    UPLOAD_APK("Send one APK for cloud inspection?",
        "AppGuardian sends the selected file to your configured server. The worker deletes its temporary copy after the request."),
    SAVE_REPORT("Save this report to your cloud account?",
        "The server receives the package identifier, fingerprints and permission list, then keeps the encrypted report for its retention period."),
    CLEAR_HISTORY("Delete cloud reports from this device?",
        "This clears the reports submitted by this device. Other device histories stay in the account."),
    DELETE_ACCOUNT("Delete this cloud account?",
        "This removes the account, devices, sessions and stored cloud reports. Local reports on this phone remain available."),
    FORGET_DEVICE("Forget device credentials on this phone?",
        "You will need to sign in as a new device. Use the account dashboard to revoke the previous device and its stored reports.")
}

@Composable
internal fun CloudPanel(review: Review?) {
    val context = LocalContext.current
    val client = remember(context) { CloudClient(context.applicationContext) }
    val scope = rememberCoroutineScope()
    var endpoint by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var enrollment by remember { mutableStateOf("") }
    var registering by remember { mutableStateOf(false) }
    var profile by remember { mutableStateOf<CloudProfile?>(null) }
    var consent by remember { mutableStateOf<ConsentAction?>(null) }
    var shareDashboard by remember { mutableStateOf(false) }
    var confirmationPassword by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var results by remember { mutableStateOf<List<CloudHistoryEntry>?>(null) }
    var inspection by remember { mutableStateOf<CloudInspection?>(null) }
    var guidance by remember { mutableStateOf<GuidedPlan?>(null) }
    var hindi by remember { mutableStateOf(false) }
    var useModel by remember { mutableStateOf(false) }

    fun task(action: suspend () -> Unit) {
        if (busy) return
        busy = true
        message = ""
        scope.launch {
            try {
                action()
            } catch (cancel: CancellationException) {
                throw cancel
            } catch (error: CloudFailure) {
                message = when (error.code) {
                    401 -> "The session or credentials are invalid. Sign in again."
                    403 -> "Enrollment requires the private code from your server operator."
                    409 -> "An account already exists. Sign in instead."
                    413 -> "Choose an APK no larger than 25 MiB."
                    422 -> "The server could not use those details or inspect the selected file."
                    429 -> "Too many requests. Wait a few minutes and try again."
                    else -> "The server could not complete the request."
                }
            } catch (_: IllegalArgumentException) {
                message = "Check the HTTPS server address and the information you entered."
            } catch (_: Exception) {
                message = "Could not connect or read the saved profile. Check the server address and connection."
            } finally {
                busy = false
            }
        }
    }

    LaunchedEffect(client) {
        try {
            profile = withContext(Dispatchers.IO) { client.profile() }
            profile?.let {
                endpoint = it.endpoint
                email = it.email
            }
        } catch (cancel: CancellationException) {
            throw cancel
        } catch (_: Exception) {
            message = "Could not read the saved profile. You can forget it and sign in again."
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        val current = profile
        if (uri != null && current != null && current.activeToken() != null) task {
            inspection = withContext(Dispatchers.IO) { client.scan(current, uri) }
        }
    }

    val session = profile?.takeIf { it.activeToken() != null }
    ElevatedCard {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Cloud account", style = MaterialTheme.typography.headlineSmall)
            Text("Optional connection to an AppGuardian server. Local scanning and recovery work without an account.")
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (message.isNotBlank()) Text(message, color = MaterialTheme.colorScheme.primary)
            if (session == null) {
                OutlinedTextField(endpoint, { endpoint = it }, Modifier.fillMaxWidth(),
                    label = { Text("HTTPS server address") }, singleLine = true)
                OutlinedTextField(email, { email = it }, Modifier.fillMaxWidth(), label = { Text("Email") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email), singleLine = true)
                OutlinedTextField(password, { password = it }, Modifier.fillMaxWidth(), label = { Text("Password") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), singleLine = true)
                if (registering) {
                    OutlinedTextField(enrollment, { enrollment = it }, Modifier.fillMaxWidth(),
                        label = { Text("Enrollment code") }, visualTransformation = PasswordVisualTransformation(),
                        singleLine = true)
                }
                Button(enabled = !busy && password.length >= 12 && email.isNotBlank() && endpoint.isNotBlank() &&
                    (!registering || enrollment.isNotBlank()), onClick = {
                    val enteredPassword = password
                    val invite = enrollment.takeIf { registering }
                    password = ""
                    enrollment = ""
                    task {
                        profile = withContext(Dispatchers.IO) { client.signIn(endpoint, email.trim(), enteredPassword, invite) }
                    }
                }) { Text(if (registering) "Create account" else "Sign in") }
                TextButton(enabled = !busy, onClick = { registering = !registering }) {
                    Text(if (registering) "Use an existing account" else "Create account with enrollment code")
                }
                if (profile != null || message.startsWith("Could not read")) {
                    TextButton(enabled = !busy, onClick = { consent = ConsentAction.FORGET_DEVICE }) {
                        Text("Forget this device")
                    }
                }
            } else {
                Text(session.email, style = MaterialTheme.typography.titleMedium)
                Text("Connected to ${session.endpoint}", style = MaterialTheme.typography.bodySmall)
                OutlinedButton(enabled = !busy, onClick = {
                    task {
                        val (signedOut, revoked) = withContext(Dispatchers.IO) { client.signOut(session) }
                        profile = signedOut
                        results = null
                        inspection = null
                        guidance = null
                        message = if (revoked) "Signed out." else "Signed out on this device. The server session could not be revoked."
                    }
                }) { Text("Sign out") }
                TextButton(enabled = !busy, onClick = {
                    confirmationPassword = ""
                    consent = ConsentAction.DELETE_ACCOUNT
                }) { Text("Delete cloud account") }
                HorizontalDivider()
                Button(enabled = !busy, onClick = { consent = ConsentAction.UPLOAD_APK }) { Text("Inspect an APK in the cloud") }
                inspection?.let { RemoteInspection(it) }
                if (review != null) {
                    OutlinedButton(enabled = !busy, onClick = {
                        shareDashboard = false
                        consent = ConsentAction.SAVE_REPORT
                    }) {
                        Text("Save current report to account")
                    }
                }
                TextButton(enabled = !busy, onClick = {
                    task { results = withContext(Dispatchers.IO) { client.history(session) } }
                }) { Text("Load device’s cloud history") }
                results?.let { history ->
                    if (history.isEmpty()) Text("No reports for this device.")
                    history.forEach { row ->
                        Text(row.name, style = MaterialTheme.typography.titleSmall)
                        val expiry = DateFormat.getDateTimeInstance().format(Date(row.expiresAt.toEpochMilli()))
                        Text("Expires $expiry", style = MaterialTheme.typography.bodySmall)
                    }
                    if (history.isNotEmpty()) {
                        TextButton(enabled = !busy, onClick = { consent = ConsentAction.CLEAR_HISTORY }) { Text("Clear cloud history") }
                    }
                }
                HorizontalDivider()
                Text("Guidance", style = MaterialTheme.typography.titleMedium)
                Text(if (review == null) "Get account incident steps." else "Use only the current report’s selected evidence categories.")
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(selected = !hindi, onClick = { hindi = false }, label = { Text("English") })
                    FilterChip(selected = hindi, onClick = { hindi = true }, label = { Text("हिन्दी") })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(useModel, onCheckedChange = { useModel = it })
                    Text("Let the configured AI provider prioritize selected evidence categories for this request.")
                }
                OutlinedButton(enabled = !busy, onClick = {
                    val consentToModel = useModel
                    useModel = false
                    task { guidance = withContext(Dispatchers.IO) { client.advise(session, review, hindi, consentToModel) } }
                }) { Text("Get guidance") }
                guidance?.let { GuidedSteps(it) }
            }
        }
    }
    consent?.let { selected ->
        AlertDialog(
            onDismissRequest = {
                consent = null
                confirmationPassword = ""
            },
            title = { Text(selected.title) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(selected.text)
                    if (selected == ConsentAction.DELETE_ACCOUNT) {
                        OutlinedTextField(
                            confirmationPassword, { confirmationPassword = it }, Modifier.fillMaxWidth(),
                            label = { Text("Confirm with your password") },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            singleLine = true
                        )
                    }
                    if (selected == ConsentAction.SAVE_REPORT) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(shareDashboard, onCheckedChange = { shareDashboard = it })
                            Text("Also share this report with my account’s signed-in dashboard.")
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    enabled = selected != ConsentAction.DELETE_ACCOUNT || confirmationPassword.length >= 12,
                    onClick = {
                        consent = null
                        val enteredPassword = confirmationPassword
                        confirmationPassword = ""
                        when (selected) {
                            ConsentAction.UPLOAD_APK -> if (session != null) picker.launch("*/*")
                            ConsentAction.SAVE_REPORT -> if (session != null && review != null) task {
                                withContext(Dispatchers.IO) { client.save(session, review, shareDashboard) }
                                message = "Encrypted report saved to this device’s cloud history."
                            }
                            ConsentAction.CLEAR_HISTORY -> if (session != null) task {
                                withContext(Dispatchers.IO) { client.clearHistory(session) }
                                results = emptyList()
                            }
                            ConsentAction.DELETE_ACCOUNT -> if (session != null) task {
                                withContext(Dispatchers.IO) { client.deleteAccount(session, enteredPassword) }
                                profile = null
                                results = null
                                inspection = null
                                guidance = null
                                message = "Cloud account and reports deleted."
                            }
                            ConsentAction.FORGET_DEVICE -> task {
                                withContext(Dispatchers.IO) { client.forget() }
                                profile = null
                                email = ""
                                message = "Device credentials removed from this phone."
                            }
                        }
                    }
                ) { Text("Confirm") }
            },
            dismissButton = {
                TextButton(onClick = {
                    consent = null
                    confirmationPassword = ""
                }) { Text("Cancel") }
            }
        )
    }
}

@Composable
private fun RemoteInspection(result: CloudInspection) {
    Text("Worker inspection", style = MaterialTheme.typography.titleMedium)
    Text(result.name)
    Text("Signature check · ${result.signature}")
    if (result.debug) Text("The manifest enables Android debugging.")
    Text("SHA-256", style = MaterialTheme.typography.labelLarge)
    Text(result.hash, style = MaterialTheme.typography.bodySmall)
    if (result.signers.isNotEmpty()) {
        Text("Signing certificate SHA-256", style = MaterialTheme.typography.labelLarge)
        result.signers.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
    Text("Requested permissions", style = MaterialTheme.typography.labelLarge)
    if (result.permissions.isEmpty()) Text("None reported by the worker.")
    result.permissions.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
}

@Composable
private fun GuidedSteps(guidance: GuidedPlan) {
    Text(
        when (guidance.mode) {
            "ai-prioritized" -> "Evidence prioritized by the configured model"
            "rules-fallback" -> "Rule-based guidance used"
            else -> "Rule-based guidance"
        },
        style = MaterialTheme.typography.labelLarge
    )
    Text(guidance.scope, style = MaterialTheme.typography.bodySmall)
    guidance.steps.forEach { (title, instruction) ->
        Text(title, style = MaterialTheme.typography.titleSmall)
        Text(instruction)
    }
}

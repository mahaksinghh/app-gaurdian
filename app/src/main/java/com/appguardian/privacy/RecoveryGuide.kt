package com.appguardian.privacy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.util.Locale

private data class Words(val english: String, val hindi: String) {
    fun choose(hindiEnabled: Boolean): String = if (hindiEnabled) hindi else english
}

private data class AccountProvider(
    val name: String,
    val security: String?,
    val recovery: String?,
    val sessions: Words
)

private val providers = listOf(
    AccountProvider(
        "Google", "https://myaccount.google.com/security", "https://accounts.google.com/signin/recovery",
        Words("Review recent security activity and your devices. Sign out of devices you do not recognize.",
            "हाल की सुरक्षा गतिविधि और अपने डिवाइस देखें। अनजान डिवाइस से साइन आउट करें।")
    ),
    AccountProvider(
        "Microsoft", "https://account.microsoft.com/security", "https://account.live.com/acsr",
        Words("Review recent activity. Sign out everywhere if you cannot recognize or remove a session.",
            "हाल की गतिविधि देखें। अगर किसी सत्र को पहचान या हटा नहीं पा रहे हैं, तो सभी जगह से साइन आउट करें।")
    ),
    AccountProvider(
        "Apple", "https://account.apple.com/", "https://iforgot.apple.com/",
        Words("Review the devices associated with your Apple Account. Remove devices you do not recognize.",
            "अपने Apple खाते से जुड़े डिवाइस देखें। अनजान डिवाइस हटाएँ।")
    ),
    AccountProvider(
        "Other", null, null,
        Words("Open the provider’s security page and sign out of unrecognized sessions.",
            "सेवा की सुरक्षा सेटिंग खोलें और अनजान सत्रों से साइन आउट करें।")
    )
)

@Composable
internal fun RecoveryGuide(openSite: (String) -> Unit) {
    var hindi by rememberSaveable { mutableStateOf(Locale.getDefault().language == "hi") }
    var providerIndex by rememberSaveable { mutableStateOf(0) }
    var confirmed by rememberSaveable { mutableStateOf(0) }
    val provider = providers[providerIndex]
    fun text(english: String, translation: String) = if (hindi) translation else english

    val steps = listOf(
        text("Change the password from a trusted device. Use a new, unique password.",
            "विश्वसनीय डिवाइस से पासवर्ड बदलें। नया और अलग पासवर्ड इस्तेमाल करें।"),
        provider.sessions.choose(hindi),
        text("Review the recovery email and phone number. Remove changes you did not make.",
            "रिकवरी ईमेल और फ़ोन नंबर देखें। जो बदलाव आपने नहीं किए, उन्हें हटाएँ।"),
        text("Turn on two-step verification and confirm that the recovery methods are yours.",
            "दो-चरणीय सत्यापन चालू करें और पुष्टि करें कि रिकवरी के तरीके आपके हैं।")
    )

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(selected = !hindi, onClick = { hindi = false }, label = { Text("English") })
            FilterChip(selected = hindi, onClick = { hindi = true }, label = { Text("हिन्दी") })
        }
        Text(text("If you suspect account access, use a device you trust.",
            "अगर खाते पर अनधिकृत पहुँच का शक है, तो विश्वसनीय डिवाइस इस्तेमाल करें।"))
        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            items(providers.indices.toList()) { index ->
                val name = if (hindi && providers[index].name == "Other") "अन्य" else providers[index].name
                FilterChip(selected = index == providerIndex, onClick = {
                    providerIndex = index
                    confirmed = 0
                }, label = { Text(name) })
            }
        }
        provider.security?.let { url ->
            Button(onClick = { openSite(url) }) { Text(text("Open account security", "खाते की सुरक्षा सेटिंग खोलें")) }
        }
        provider.recovery?.let { url ->
            OutlinedButton(onClick = { openSite(url) }) { Text(text("I can’t sign in", "मैं साइन इन नहीं कर पा रहा हूँ")) }
        }
        Text(text("Confirm each step after checking your account.", "खाते में जाँच करने के बाद हर चरण की पुष्टि करें।"),
            style = MaterialTheme.typography.titleSmall)
        steps.forEachIndexed { index, action ->
            val bit = 1 shl index
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = confirmed and bit != 0,
                    onCheckedChange = { checked -> confirmed = if (checked) confirmed or bit else confirmed and bit.inv() }
                )
                Text(action, Modifier.padding(start = 4.dp))
            }
        }
        Text(
            text("${confirmed.countOneBits()} of ${steps.size} steps you confirmed",
                "${steps.size} में से ${confirmed.countOneBits()} चरणों की आपने पुष्टि की"),
            style = MaterialTheme.typography.bodySmall
        )
    }
}

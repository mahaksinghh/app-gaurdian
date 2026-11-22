package com.appguardian.privacy

internal data class Finding(val title: String, val explanation: String)

internal object Evidence {
    private val sensitive = mapOf(
        "READ_SMS" to "Read text messages, which may contain verification codes.",
        "RECEIVE_SMS" to "Receive incoming text messages.",
        "READ_CONTACTS" to "Read saved contacts.",
        "RECORD_AUDIO" to "Record sound when Android allows microphone access.",
        "CAMERA" to "Use the device camera when Android allows access.",
        "ACCESS_FINE_LOCATION" to "Access precise location when Android allows it.",
        "ACCESS_BACKGROUND_LOCATION" to "Request location while running in the background."
    )

    fun review(
        permissions: Set<String>,
        debuggable: Boolean,
        accessibilityService: Boolean,
        testOnly: Boolean = false,
        cleartextOptIn: Boolean = false
    ): List<Finding> = buildList {
        sensitive.forEach { (name, explanation) ->
            if ("android.permission.$name" in permissions) {
                add(Finding(name, explanation))
            }
        }
        if ("android.permission.REQUEST_INSTALL_PACKAGES" in permissions) {
            add(Finding("Request app installs", "The app can ask Android to install another package. Android applies its own approvals."))
        }
        if (accessibilityService) {
            add(Finding("Accessibility service", "If enabled, accessibility access can let an app read screen content or interact with other apps, depending on its configuration."))
        }
        if (debuggable) {
            add(Finding("Debuggable build", "The manifest allows app debugging. Confirm that this is the build you expected from the publisher."))
        }
        if (testOnly) {
            add(Finding("Test-only build", "The manifest marks this package for testing. Confirm you intended to receive a test build."))
        }
        if (cleartextOptIn) {
            add(Finding("Cleartext traffic opt-in", "The manifest explicitly opts into unencrypted connections. Android version and network security configuration can affect enforcement."))
        }
    }

    fun changedGrants(previous: Set<String>, current: Set<String>): List<String> =
        ((current - previous).sorted().map { "Granted: $it" } +
            (previous - current).sorted().map { "Revoked: $it" })
}

#!/usr/bin/env bash
set -euo pipefail

adb shell settings put global hide_error_dialogs 1
adb shell wm size 1080x1920
adb shell wm density 400
adb reverse tcp:18443 tcp:18443
certificate="$(base64 -w0 "$RUNNER_TEMP/appguardian-tls/server.crt")"
gradle --no-daemon connectedDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=com.appguardian.privacy.PilotIntegrationTest \
    -Pandroid.testInstrumentationRunnerArguments.pilotUrl=https://127.0.0.1:18443 \
    "-Pandroid.testInstrumentationRunnerArguments.pilotCertificate=$certificate" \
    "-Pandroid.testInstrumentationRunnerArguments.pilotEnrollment=$GUARDIAN_ENROLLMENT_SECRET" \
    -Pandroid.testInstrumentationRunnerArguments.pilotVpn=true

mkdir -p app/build/pilot-preview
for name in pilot-home.png pilot-dns.png; do
    adb exec-out run-as com.appguardian.privacy cat "cache/$name" > "app/build/pilot-preview/$name"
    test -s "app/build/pilot-preview/$name"
done

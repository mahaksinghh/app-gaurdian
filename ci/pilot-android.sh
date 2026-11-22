#!/usr/bin/env bash
set -euo pipefail

adb shell settings put global hide_error_dialogs 1
adb shell wm size 1080x1920
adb shell wm density 400
adb reverse tcp:18443 tcp:18443
bash ci/build-probe.sh
certificate="$(base64 -w0 "$RUNNER_TEMP/appguardian-tls/server.crt")"
test_status=0
gradle --no-daemon connectedDebugAndroidTest \
    -Pandroid.testInstrumentationRunnerArguments.class=com.appguardian.privacy.PilotIntegrationTest \
    -Pandroid.testInstrumentationRunnerArguments.pilotUrl=https://127.0.0.1:18443 \
    "-Pandroid.testInstrumentationRunnerArguments.pilotCertificate=$certificate" \
    "-Pandroid.testInstrumentationRunnerArguments.pilotEnrollment=$GUARDIAN_ENROLLMENT_SECRET" \
    -Pandroid.testInstrumentationRunnerArguments.pilotVpn=true || test_status=$?

mkdir -p app/build/pilot-preview
for name in pilot-home.png pilot-dns.png; do
    if adb exec-out cat "/data/local/tmp/appguardian-$name" > "app/build/pilot-preview/$name"; then
        if ! python3 -c 'from pathlib import Path; import sys; assert Path(sys.argv[1]).read_bytes().startswith(bytes.fromhex("89504e470d0a1a0a"))' "app/build/pilot-preview/$name"; then
            rm -f "app/build/pilot-preview/$name"
            test_status=1
        fi
    else
        rm -f "app/build/pilot-preview/$name"
        test_status=1
    fi
done
exit "$test_status"

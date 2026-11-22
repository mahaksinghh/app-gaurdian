#!/usr/bin/env bash
set -euo pipefail

probe_dir="$(mktemp -d)"
trap 'rm -rf "$probe_dir"' EXIT
android_jar="$ANDROID_HOME/platforms/android-35/android.jar"
tools="$ANDROID_HOME/build-tools/35.0.0"
mkdir "$probe_dir/classes" "$probe_dir/dex"
javac --release 8 -classpath "$android_jar" -d "$probe_dir/classes" ci/fixtures/ProbeActivity.java
"$tools/d8" --lib "$android_jar" --min-api 28 --output "$probe_dir/dex" \
    "$probe_dir/classes/com/appguardian/probe/ProbeActivity.class"
"$tools/aapt" package -f -M ci/fixtures/AndroidManifest.xml -I "$android_jar" -F "$probe_dir/packed.apk"
zip -q -j "$probe_dir/packed.apk" "$probe_dir/dex/classes.dex"
"$tools/zipalign" -f 4 "$probe_dir/packed.apk" "$probe_dir/aligned.apk"
keytool -genkeypair -keyalg RSA -keysize 2048 -validity 2 -dname "CN=AppGuardian Test Probe" \
    -alias probe -keystore "$probe_dir/probe.jks" -storepass fixture-ci -keypass fixture-ci
"$tools/apksigner" sign --ks "$probe_dir/probe.jks" --ks-pass pass:fixture-ci \
    --out "$probe_dir/probe.apk" "$probe_dir/aligned.apk"
adb install -r "$probe_dir/probe.apk"

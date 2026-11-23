#!/usr/bin/env bash
set -euo pipefail

fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT
tools="$ANDROID_HOME/build-tools/35.0.0"
fixture="$fixture_dir/sample.apk"
cat > "$fixture_dir/AndroidManifest.xml" <<'MANIFEST'
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.guardian.fixture" android:versionCode="1" android:versionName="1">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35" />
    <uses-permission android:name="android.permission.CAMERA" />
    <application android:debuggable="true" android:label="AppGuardian CI Fixture" />
</manifest>
MANIFEST
"$tools/aapt" package -f -M "$fixture_dir/AndroidManifest.xml" \
    -I "$ANDROID_HOME/platforms/android-35/android.jar" -F "$fixture_dir/unsigned.apk"
keytool -genkeypair -keyalg RSA -keysize 2048 -dname "CN=AppGuardian Test Fixture" \
    -validity 2 -alias fixture -keystore "$fixture_dir/fixture.jks" -storepass fixture-ci \
    -keypass fixture-ci
"$tools/apksigner" sign --ks "$fixture_dir/fixture.jks" --ks-pass pass:fixture-ci \
    --out "$fixture" "$fixture_dir/unsigned.apk"

python3 - "$fixture" "$fixture_dir/unsigned.apk" <<'PY'
from hashlib import sha256
from json import dumps, loads
from os import environ
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4
import sys

def request(path, data, headers):
    try:
        with urlopen(Request("http://localhost:8000" + path, data=data, headers=headers), timeout=75) as response:
            return response.status, loads(response.read())
    except HTTPError as error:
        return error.code, loads(error.read())

status, session = request("/v1/auth/register", dumps({
    "email": f"fixture-{uuid4()}@example.test",
    "password": "fixture-ci-only-password",
    "enrollment_secret": environ["GUARDIAN_ENROLLMENT_SECRET"],
}).encode(), {"Content-Type": "application/json"})
assert status == 201, session
headers = {
    "Content-Type": "application/vnd.android.package-archive",
    "Authorization": f"Bearer {session['token']}",
}
endpoint = "/v1/archives/scan"
signed = Path(sys.argv[1]).read_bytes()
assert request(endpoint, signed, headers)[0] == 400
headers["X-AppGuardian-Scan-Consent"] = "true"
assert request(endpoint, signed, {"X-AppGuardian-Scan-Consent": "true"})[0] == 401
status, evidence = request(endpoint, signed, headers)
assert status == 200, evidence
assert evidence["signature"] == "verified", evidence
assert evidence["debuggable"] is True
assert evidence["report"]["apk_sha256"] == sha256(signed).hexdigest()
assert evidence["report"]["package_name"] == "com.example.guardian.fixture"
assert evidence["report"]["requested_permissions"] == ["android.permission.CAMERA"]
assert len(evidence["report"]["signer_sha256"]) >= 1

status, evidence = request(endpoint, Path(sys.argv[2]).read_bytes(), headers)
assert status == 200 and evidence["signature"] == "unverified", evidence
assert request(endpoint, b"invalid APK", headers)[0] == 422
print("Signed, unsigned and malformed APKs inspected through the isolated worker.")

json_headers = {"Content-Type": "application/json", "Authorization": headers["Authorization"]}
status, guidance = request("/v1/guide", dumps({
    "scenario": "before-install", "language": "hi", "evidence": ["debuggable", "camera"], "use_ai": True,
}).encode(), json_headers)
assert status == 200 and guidance["mode"] == "rules-fallback", guidance
assert guidance["steps"][-1]["id"] == "verify"

status, assessment = request("/v1/assessments/kev", dumps({
    "cve_ids": ["CVE-2021-44228", "CVE-2050-00000"],
}).encode(), json_headers)
assert status == 200 and assessment["license"] == "CC0-1.0", assessment
assert [item["cveID"] for item in assessment["matches"]] == ["CVE-2021-44228"]
assert assessment["unlisted_ids"] == ["CVE-2050-00000"]
print("Bilingual guidance and licensed exact-ID vulnerability lookup passed.")
PY

test "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$(docker compose ps -q worker)")" = none
test -z "$(docker compose exec -T worker find /tmp -maxdepth 1 -name 'guardian-*' -print)"

if [[ -n "${GUARDIAN_BROWSER_APK:-}" ]]; then
    cp "$fixture" "$GUARDIAN_BROWSER_APK"
fi

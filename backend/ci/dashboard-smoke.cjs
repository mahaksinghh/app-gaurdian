const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { chromium } = require(process.env.GUARDIAN_PLAYWRIGHT_DIR + "/node_modules/playwright");

const origin = "http://127.0.0.1:8000";
const email = `dashboard-${randomUUID()}@example.test`;
const password = "dashboard-ci-password";

async function request(path, method, body, token) {
  const response = await fetch(origin + path, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: "Bearer " + token } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  return [response.status, response.status === 204 ? null : await response.json()];
}

(async () => {
  const [status, android] = await request("/v1/auth/register", "POST", {
    email, password, enrollment_secret: process.env.GUARDIAN_ENROLLMENT_SECRET,
  });
  assert.equal(status, 201);
  for (const share of [true, false]) {
    const [result] = await request("/v1/scans", "POST", {
      consent: { store_report: true, allow_account_dashboard: share },
      report: {
        kind: "installed",
        package_name: share ? "com.example.guardian.shared" : "com.example.guardian.private",
        version: "1",
        signer_sha256: [],
        requested_permissions: ["android.permission.CAMERA"],
        granted_permissions: ["android.permission.CAMERA"],
      },
    }, android.token);
    assert.equal(result, 201);
  }
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 960 } });
    await page.goto(origin + "/dashboard/");
    await page.getByRole("heading", { name: "What do you want to protect?" }).waitFor();
    await page.getByRole("button", { name: "Try a sample safety check" }).click();
    await page.getByRole("button", { name: "Check the sample" }).click();
    await page.getByRole("heading", { name: "The sample requests SMS access" }).waitFor();
    await page.getByRole("button", { name: "See what to do" }).click();
    await page.getByRole("button", { name: "Verify before deciding" }).click();
    await page.getByRole("heading", { name: "Check the source and file" }).waitFor();
    await page.getByRole("button", { name: "Close demo" }).click();
    await page.getByRole("button", { name: "Check a file" }).click();
    await page.getByLabel("Select an Android APK").setInputFiles({
      name: "fingerprint-fixture.apk", mimeType: "application/vnd.android.package-archive", buffer: Buffer.from("abc")
    });
    await page.getByRole("button", { name: "Compare fingerprint" }).click();
    await page.getByText(/ba7816bf8f01cfea414140de5dae2223/).waitFor();
    await page.getByRole("dialog").getByRole("button", { name: "Close" }).click();
    await page.getByRole("button", { name: "Start recovery" }).click();
    await page.getByLabel("Change the password from a trusted device.").check();
    await page.getByText("1 of 4 steps confirmed by you.").waitFor();
    await page.getByRole("dialog").getByRole("button", { name: "Close" }).click();
    await page.getByRole("button", { name: "Check a file" }).click();
    await page.getByLabel("Select an Android APK").setInputFiles(process.env.GUARDIAN_BROWSER_APK);
    await page.getByRole("button", { name: "Sign in to inspect" }).click();
    await page.getByRole("heading", { name: "Sign in" }).waitFor();
    await page.locator("#login").getByLabel("Email", { exact: true }).fill(email);
    await page.locator("#login").getByLabel("Password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Sign in" }).click();
    const scan = page.getByRole("dialog", { name: "Check an Android app file" });
    await scan.getByRole("button", { name: "Inspect on server" }).click();
    await scan.getByText("Confirm that you want to send this APK to the server.").waitFor();
    await scan.getByLabel("Send this APK to my AppGuardian server for one-time inspection.").check();
    await scan.getByRole("button", { name: "Inspect on server" }).click();
    await scan.getByRole("heading", { name: "Pause and review before installing" }).waitFor();
    await scan.getByText("Use the camera.", { exact: true }).waitFor();
    await scan.getByRole("heading", { name: "How to verify" }).waitFor();
    await scan.getByRole("button", { name: "Close" }).click();
    console.log("Signed APK inspected from the browser with explicit consent and decision guidance.");

    await page.getByText("com.example.guardian.shared", { exact: true }).waitFor();
    assert.equal(await page.getByText("com.example.guardian.private", { exact: true }).count(), 0);
    await page.getByText("com.example.guardian.shared", { exact: true }).click();
    await page.getByText("android.permission.CAMERA · Granted").waitFor();

    await page.getByRole("button", { name: "CVE assessment" }).click();
    await page.getByLabel("CVE identifiers").fill("CVE-2021-44228, CVE-2050-00000");
    await page.getByRole("button", { name: "Look up identifiers" }).click();
    await page.getByRole("heading", { name: "CVE-2021-44228" }).waitFor();
    await page.getByText("Unlisted in this release · CVE-2050-00000").waitFor();
    await page.screenshot({ path: "dashboard-preview.png" });

    await page.getByRole("button", { name: "Devices", exact: true }).click();
    const device = page.locator("article").filter({ hasText: "Device " + android.device_id.slice(0, 8) });
    await device.getByRole("button", { name: "Revoke device" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Revoke device" }).click();
    await page.getByText("Device revoked.").waitFor();
    assert.equal((await request("/v1/scans", "GET", null, android.token))[0], 401);

    await page.getByRole("button", { name: "Sign out" }).click();
    await page.getByRole("heading", { name: "Sign in" }).waitFor();
    console.log("Dashboard sign-in, shared review, CVE lookup, device revocation, and sign-out passed.");
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

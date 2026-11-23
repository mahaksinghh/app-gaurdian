"use strict";

const scanDialog = byId("scan-dialog");
const recoveryDialog = byId("recovery-dialog");
const fileField = byId("apk-file");
const consentField = byId("upload-consent");
const hashResult = byId("hash-result");
const inspectStatus = byId("inspect-status");
const inspectionResult = byId("inspection-result");
const archiveLimit = 25 * 1024 * 1024;
let installPrompt;
let scanRevision = 0;

byId("open-scan").onclick = () => scanDialog.showModal();
byId("open-recovery").onclick = () => recoveryDialog.showModal();
byId("open-reports").onclick = () => {
  if (session) {
    showPanel("reports");
    withSession(fetchReports);
    byId("workspace").scrollIntoView();
  } else {
    login.scrollIntoView();
    login.elements.email.focus();
  }
};

fileField.onchange = () => {
  scanRevision++;
  consentField.checked = false;
  hashResult.textContent = "";
  inspectStatus.textContent = "";
  inspectionResult.replaceChildren();
};

function selectedArchive() {
  const file = fileField.files[0];
  if (!file || !/\.apk$/i.test(file.name) || file.size === 0 || file.size > archiveLimit) {
    throw new Error("Choose a non-empty APK up to 25 MiB.");
  }
  return file;
}

byId("hash-apk").onclick = async () => {
  const revision = scanRevision;
  try {
    const file = selectedArchive();
    const expected = byId("expected-hash").value.replace(/[\s:]/g, "").toLowerCase();
    if (expected && !/^[a-f0-9]{64}$/.test(expected)) throw new Error("Enter a 64-character SHA-256 fingerprint.");
    if (!crypto.subtle) throw new Error("Open AppGuardian over HTTPS to compare fingerprints.");
    const bytes = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    if (revision !== scanRevision) return;
    const actual = Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("");
    const match = expected ? (expected === actual ? "Matches the publisher value. " : "Values differ. Verify the download source before installing. ") : "";
    hashResult.textContent = match + "SHA-256 " + actual;
  } catch (error) {
    if (revision === scanRevision) hashResult.textContent = error.message;
  }
};

byId("inspect-apk").onclick = async () => {
  const button = byId("inspect-apk");
  const revision = scanRevision;
  inspectionResult.replaceChildren();
  try {
    const file = selectedArchive();
    if (!session) throw new Error("Close this panel, sign in, then open Check a file again.");
    if (!consentField.checked) throw new Error("Confirm that you want to send this APK to the server.");
    const current = session;
    consentField.checked = false;
    button.disabled = true;
    inspectStatus.textContent = "Inspecting APK…";
    const response = await fetch(current.endpoint + "/v1/archives/scan", {
      method: "POST", body: file, credentials: "omit", cache: "no-store", redirect: "error",
      headers: { Authorization: "Bearer " + current.token, "Content-Type": "application/vnd.android.package-archive", "X-AppGuardian-Scan-Consent": "true" }
    });
    if (response.status === 503) throw new Error("APK inspection is unavailable on this server. Local fingerprint comparison is still available.");
    if (response.status === 401) throw new Error("Your session has ended. Sign in again.");
    if (response.status === 422) throw new Error("The server could not read this APK.");
    if (!response.ok) throw new Error("The server could not inspect this APK.");
    const result = await response.json();
    if (current !== session || revision !== scanRevision) return;
    const report = result.report;
    inspectionResult.append(element("h3", "What to do next"),
      element("p", result.signature === "verified"
        ? "Confirm the publisher and check why the app needs the permissions below before installing."
        : "Pause the installation. Get the app from the developer’s official source and compare its fingerprint."),
      element("h3", report.package_name),
      element("p", "Signing check: " + result.signature),
      element("p", "APK SHA-256 " + report.apk_sha256, "hash"));
    if (result.debuggable) inspectionResult.append(element("p", "The manifest enables debugging. Confirm this build with the publisher."));
    const permissions = element("ul");
    for (const permission of report.requested_permissions) permissions.append(element("li", permission));
    inspectionResult.append(element("h3", "Requested permissions"), permissions);
    if (!report.requested_permissions.length) inspectionResult.append(element("p", "None reported."));
    inspectionResult.append(element("p", "Check the download source and whether these permissions fit the app’s purpose before installing."));
    inspectStatus.textContent = "";
  } catch (error) {
    if (revision === scanRevision) inspectStatus.textContent = error instanceof TypeError ? "Could not reach your AppGuardian server." : error.message;
  } finally {
    button.disabled = false;
  }
};

const recoverySteps = {
  en: ["Change the password from a trusted device.", "Review recent sign-ins and remove unknown devices.", "Verify your recovery email and phone number.", "Turn on two-step verification and confirm it in account settings."],
  hi: ["विश्वसनीय डिवाइस से पासवर्ड बदलें।", "हाल के साइन-इन देखें और अनजान डिवाइस हटाएँ।", "रिकवरी ईमेल और फ़ोन नंबर की पुष्टि करें।", "दो-चरणीय सत्यापन चालू करें और खाते की सेटिंग में उसकी पुष्टि करें।"]
};
const completed = new Set();
function renderRecovery() {
  const language = byId("recovery-language").value;
  const checklist = byId("recovery-checklist");
  const update = () => {
    byId("recovery-status").textContent = language === "hi"
      ? completed.size + "/4 चरणों की आपने पुष्टि की।"
      : completed.size + " of 4 steps confirmed by you.";
  };
  checklist.replaceChildren();
  recoverySteps[language].forEach((step, index) => {
    const label = element("label", undefined, "check-label");
    const checkbox = element("input");
    checkbox.type = "checkbox";
    checkbox.checked = completed.has(index);
    checkbox.onchange = () => {
      if (checkbox.checked) completed.add(index);
      else completed.delete(index);
      update();
    };
    label.append(checkbox, document.createTextNode(step));
    checklist.append(label);
  });
  update();
}
byId("recovery-language").onchange = renderRecovery;
renderRecovery();

window.addEventListener("beforeinstallprompt", event => {
  event.preventDefault();
  installPrompt = event;
});
byId("install-app").onclick = async () => {
  if (!installPrompt) return byId("install-dialog").showModal();
  const prompt = installPrompt;
  installPrompt = undefined;
  await prompt.prompt();
};
if ("serviceWorker" in navigator) navigator.serviceWorker.register("./service-worker.js").catch(console.warn);


const walkthrough = byId("walkthrough");
const walkthroughTitle = byId("walkthrough-title");
const walkthroughDetail = byId("walkthrough-detail");
const walkthroughNext = byId("walkthrough-next");
const walkthroughSteps = [
  ["Someone sent you a photo editor APK", "You received an Android installation file in a message. Try a safety check before deciding whether to install it.", "Check the sample"],
  ["The sample requests SMS access", "SMS access could let an app read text messages if Android grants it. In this example, the sender has not explained why a photo editor needs that access.", "See what to do"],
  ["Pause the installation", "Leave the file uninstalled for now. Open the developer’s official site independently and check whether they offer the same app and explain the permission.", "Verify before deciding"],
  ["Check the source and file", "If the developer publishes a SHA-256 file fingerprint, compare it with your download. If you cannot verify the source or explain the SMS request, leave it uninstalled.", "Start over"]
];
let walkthroughIndex = 0;
function showWalkthroughStep() {
  const [title, detail, action] = walkthroughSteps[walkthroughIndex];
  walkthroughTitle.textContent = title;
  walkthroughDetail.textContent = detail;
  walkthroughNext.textContent = action;
}
byId("open-walkthrough").onclick = () => {
  walkthroughIndex = 0;
  showWalkthroughStep();
  walkthrough.showModal();
};
walkthroughNext.onclick = () => {
  walkthroughIndex = (walkthroughIndex + 1) % walkthroughSteps.length;
  showWalkthroughStep();
};

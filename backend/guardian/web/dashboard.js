"use strict";

const byId = (id) => document.getElementById(id);
const login = byId("login");
const status = byId("status");
const loginStatus = byId("login-status");
const revokeDialog = byId("revoke-dialog");
let session = null;
let revoking = null;
let pending = false;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function endpointFor(value) {
  const url = new URL(value.trim() || window.location.origin);
  const local = url.origin === window.location.origin && ["localhost", "127.0.0.1"].includes(url.hostname);
  if ((!local && url.protocol !== "https:") || url.username || url.password || url.search || url.hash) {
    throw new Error("Enter the HTTPS address of your AppGuardian server.");
  }
  return url.href.replace(/\/$/, "");
}

async function request(endpoint, path, { token, method = "GET", body } = {}) {
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = "Bearer " + token;
  if (body) headers["Content-Type"] = "application/json";
  const response = await fetch(endpoint + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
    credentials: "omit", cache: "no-store", redirect: "error",
  });
  if (!response.ok) {
    if (response.status === 401) throw new Error("Credentials are invalid or the session has ended.");
    if (response.status === 503) throw new Error("This service is currently unavailable on your server.");
    if (response.status === 422) throw new Error("Check the information you entered.");
    throw new Error("The server could not complete the request.");
  }
  return response.status === 204 ? null : response.json();
}

function localDate(value) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

async function withSession(action) {
  if (!session || pending) return;
  pending = true;
  status.textContent = "";
  try {
    await action(session);
  } catch (error) {
    status.textContent = error instanceof TypeError ? "Could not reach your server." : error.message;
  } finally {
    pending = false;
  }
}

function showPanel(id) {
  for (const button of document.querySelectorAll("[data-panel]")) {
    const active = button.dataset.panel === id;
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
    byId(button.dataset.panel).hidden = !active;
  }
}

function resetSession() {
  session = null;
  byId("inspection-result").replaceChildren();
  byId("inspect-status").textContent = "";
  byId("upload-consent").checked = false;
  status.textContent = "";
  byId("locked").hidden = false;
  byId("workspace").hidden = true;
  byId("sign-out").hidden = true;
  for (const id of ["reports-list", "device-list", "assessment-result"]) byId(id).replaceChildren();
}

login.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fields = new FormData(login);
  const submit = login.querySelector("button");
  submit.disabled = true;
  loginStatus.textContent = "";
  try {
    const endpoint = endpointFor(String(fields.get("endpoint")));
    const current = await request(endpoint, "/v1/auth/login", {
      method: "POST", body: { email: String(fields.get("email")).trim(), password: fields.get("password") },
    });
    session = { endpoint, token: current.token, device: current.device_id };
    byId("connected-server").textContent = new URL(endpoint).host;
    byId("locked").hidden = true;
    byId("workspace").hidden = false;
    byId("sign-out").hidden = false;
    showPanel("reports");
    await withSession(fetchReports);
    byId("workspace").scrollIntoView();
  } catch (error) {
    loginStatus.textContent = error instanceof TypeError ? "Could not reach your server." : error.message;
  } finally {
    login.elements.password.value = "";
    submit.disabled = false;
  }
});

byId("sign-out").addEventListener("click", () => withSession(async (current) => {
  try {
    await request(current.endpoint, "/v1/auth/logout", { token: current.token, method: "POST" });
    loginStatus.textContent = "Signed out.";
  } catch {
    loginStatus.textContent = "Signed out here. The server session could not be revoked.";
  } finally {
    resetSession();
  }
}));

async function fetchReports(current) {
  const reports = await request(current.endpoint, "/v1/account/scans", current);
  const list = byId("reports-list");
  list.replaceChildren();
  if (!reports.length) list.append(element("p", "No reports have been shared to this account.", "card"));
  for (const record of reports) {
    const { report } = record;
    const entry = element("details");
    entry.append(element("summary", report.package_name));
    entry.append(element("p", `Device-reported · ${report.kind === "apk" ? "APK" : "Installed app"} · Expires ${localDate(record.expires_at)}`, "detail-meta"));
    entry.append(element("p", "Version " + report.version));
    if (report.apk_sha256) {
      entry.append(element("h3", "APK SHA-256"), element("p", report.apk_sha256, "hash"));
    }
    if (report.signer_sha256.length) {
      entry.append(element("h3", "Signing certificate SHA-256"));
      for (const signer of report.signer_sha256) entry.append(element("p", signer, "hash"));
    }
    entry.append(element("h3", "Requested permissions"));
    if (!report.requested_permissions.length) entry.append(element("p", "None reported."));
    else {
      const permissions = element("ul");
      for (const permission of report.requested_permissions) {
        const granted = report.granted_permissions.includes(permission) ? " · Granted" : "";
        permissions.append(element("li", permission + granted));
      }
      entry.append(permissions);
    }
    list.append(entry);
  }
}

async function fetchDevices(current) {
  const devices = await request(current.endpoint, "/v1/devices", current);
  const list = byId("device-list");
  list.replaceChildren();
  for (const device of devices) {
    const row = element("article", undefined, "device");
    const description = element("div");
    description.append(element("h3", device.current ? "This browser session" : "Device " + device.id.slice(0, 8)));
    description.append(element("p", device.revoked_at ? "Revoked " + localDate(device.revoked_at) : "Enrolled " + localDate(device.created_at)));
    row.append(description);
    if (!device.revoked_at) {
      const revoke = element("button", "Revoke device", "quiet");
      revoke.type = "button";
      revoke.addEventListener("click", () => {
        revoking = device;
        revokeDialog.showModal();
      });
      row.append(revoke);
    }
    list.append(row);
  }
}

byId("revoke-cancel").addEventListener("click", () => revokeDialog.close());
byId("revoke-confirm").addEventListener("click", () => {
  const device = revoking;
  revokeDialog.close();
  if (!device || !/^[\da-f-]{36}$/i.test(device.id)) return;
  withSession(async (current) => {
    await request(current.endpoint, "/v1/devices/" + device.id, { token: current.token, method: "DELETE" });
    if (device.current) {
      loginStatus.textContent = "This browser device was revoked.";
      resetSession();
    } else {
      await fetchDevices(current);
      status.textContent = "Device revoked.";
    }
  });
});

for (const button of document.querySelectorAll("[data-panel]")) {
  button.addEventListener("click", () => {
    showPanel(button.dataset.panel);
    if (button.dataset.panel === "reports") withSession(fetchReports);
    if (button.dataset.panel === "devices") withSession(fetchDevices);
  });
}
byId("refresh-reports").addEventListener("click", () => withSession(fetchReports));
byId("refresh-devices").addEventListener("click", () => withSession(fetchDevices));

byId("assess").addEventListener("submit", (event) => {
  event.preventDefault();
  const ids = [...new Set(new FormData(event.currentTarget).get("identifiers").toUpperCase().split(/[\s,]+/).filter(Boolean))];
  const result = byId("assessment-result");
  result.replaceChildren();
  if (!ids.length || ids.length > 50 || ids.some((id) => !/^CVE-\d{4}-\d{4,19}$/.test(id))) {
    status.textContent = "Enter up to 50 valid CVE identifiers.";
    return;
  }
  withSession(async (current) => {
    const data = await request(current.endpoint, "/v1/assessments/kev", {
      token: current.token, method: "POST", body: { cve_ids: ids },
    });
    const source = element("a", "CISA catalog and license");
    source.href = "https://github.com/cisagov/kev-data";
    source.target = "_blank";
    source.rel = "noopener noreferrer";
    const provenance = element("div", undefined, "result");
    provenance.append(element("h3", "Catalog " + data.catalog_version));
    provenance.append(element("p", data.stale ? "This catalog is older than 14 days." : "Released " + localDate(data.released_at)));
    provenance.append(source);
    result.append(provenance);
    for (const match of data.matches) {
      const finding = element("article", undefined, "result");
      finding.append(element("h3", match.cveID), element("p", match.vendorProject + " · " + match.product));
      finding.append(element("p", match.requiredAction));
      result.append(finding);
    }
    if (data.unlisted_ids.length) {
      result.append(element("p", "Unlisted in this release · " + data.unlisted_ids.join(", "), "result"));
    }
  });
});

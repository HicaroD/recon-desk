const explanations = {
  "storage-sensitive":
    "A token in browser storage may be accessible to page scripts. Check its scope and lifetime.",
  "cookie-httponly":
    "Page scripts can read this session-like cookie. Review whether it should be HttpOnly.",
  "cookie-secure":
    "This session-like cookie is not restricted to HTTPS requests.",
  "header-csp":
    "No enforced CSP was seen on the document response. This is a defense-in-depth lead.",
  "header-csp-unsafe-inline":
    "The observed CSP permits inline scripts without a nonce or hash. Review whether this is necessary.",
  "header-csp-wildcard-script":
    "The observed CSP allows scripts from any source. Review whether script origins can be restricted.",
  "header-csp-no-script-restriction":
    "The observed CSP does not restrict script sources. Other directives may still provide protection.",
  "header-hsts": "No HSTS header was seen on the HTTPS document response.",
  "header-hsts-disabled":
    "The observed HSTS header has no valid positive max-age, so it does not enable HSTS protection.",
  "supabase-secret":
    "A server-only Supabase key appears in content available to browser code.",
  "private-key":
    "A private key appears in JavaScript available to browser code.",
  "url-sensitive":
    "URL query values may be saved in logs, browser history, or referrer data.",
  "url-fragment-token":
    "A token in the URL fragment remains accessible to page scripts and browser history.",
  "password-form-http":
    "This password form submits to an unencrypted HTTP endpoint.",
  "dom-location-html":
    "Page-controlled URL content is assigned directly to HTML. Check whether it can inject markup or script.",
  "supabase-service-role":
    "A JWT claims the Supabase service role. Check whether it is a live privileged key.",
  "firebase-service-account":
    "Firebase service-account credentials appear in browser-accessible data.",
  "next-runtime-config":
    "Next.js server runtime configuration appears in page hydration data. Review its contents.",
  "hydration-token":
    "An authentication token appears in client hydration data. Review its scope and lifetime.",
};
const renderedStates = new WeakMap();

async function showPopup(api, doc) {
  const summary = doc.getElementById("summary");
  const status = doc.getElementById("status");
  const list = doc.getElementById("findings");
  const coverage = doc.getElementById("coverage");
  const refresh = () =>
    doc.defaultView?.setTimeout(() => {
      void showPopup(api, doc);
    }, 1000);
  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    if (!tab || !/^https?:/.test(tab.url || "")) {
      renderedStates.delete(doc);
      list.replaceChildren();
      summary.textContent = "Page unavailable";
      status.textContent = "Firefox does not allow scanning this page.";
      return;
    }
    let result;
    try {
      result = await api.runtime.sendMessage({
        type: "get-scan-state",
        tabId: tab.id,
      });
    } catch {
      renderedStates.delete(doc);
      list.replaceChildren();
      summary.textContent = "Background error";
      status.textContent =
        "Reload Client Watcher in about:debugging. If it repeats, click Inspect on its entry and check the first error.";
      return;
    }
    if (
      !result ||
      !["waiting", "scanning", "complete", "error"].includes(result.status) ||
      !Array.isArray(result.findings)
    ) {
      renderedStates.delete(doc);
      list.replaceChildren();
      summary.textContent = "Reload add-on";
      status.textContent =
        "The popup and background may be different versions. Open about:debugging, click This Firefox, then Reload Client Watcher.";
      return;
    }
    const renderKey = JSON.stringify([tab.id, tab.url, result]);
    if (renderedStates.get(doc) === renderKey) {
      refresh();
      return;
    }
    renderedStates.set(doc, renderKey);
    list.replaceChildren();
    if (coverage) {
      const names = {
        storage: "Storage",
        inlineScripts: "Inline scripts",
        forms: "Forms",
        headers: "Headers",
        cookies: "Cookies",
        externalScripts: "External scripts",
      };
      coverage.textContent = result.coverage
        ? `Scan coverage · ${Object.entries(names)
            .map(([key, label]) =>
              `${label}: ${result.coverage[key] || "not inspected"}`.replace(
                "not-inspected",
                "not inspected",
              ),
            )
            .join(" · ")} · Checked means sampled, not exhaustive.`
        : "";
    }
    if (result.status === "waiting" || result.status === "scanning") {
      summary.textContent =
        result.status === "waiting" ? "Waiting for page" : "Scanning…";
      status.textContent =
        result.status === "waiting"
          ? "Reload this tab to start a scan."
          : "Checking the current page. Findings may appear as it loads.";
      refresh();
      return;
    }
    const findings = result.findings || [];
    if (result.status === "error") {
      summary.textContent = "Scan failed";
      status.textContent =
        "The page scan could not finish. Reload the tab to retry.";
    } else {
      summary.textContent = findings.length
        ? `${findings.length} finding${findings.length === 1 ? "" : "s"}`
        : "No findings";
      status.textContent = findings.length
        ? "Review these passive signals before reporting."
        : "No matching signals in the sampled checks. This does not rule out vulnerabilities.";
    }
    if (!findings.length) {
      const empty = doc.createElement("p");
      empty.textContent =
        result.status === "error"
          ? "Some signals may not have been checked."
          : "Nothing flagged by the current checks.";
      list.appendChild(empty);
    }
    for (const item of findings) {
      const card = doc.createElement("article");
      card.className = `finding ${item.severity}`;
      const heading = doc.createElement("h2");
      heading.textContent = item.title;
      const meta = doc.createElement("p");
      meta.textContent = `${item.severity.toUpperCase()} · ${item.confidence} · ${item.url}`;
      const evidence = doc.createElement("p");
      evidence.textContent = item.evidence;
      const explanation = doc.createElement("p");
      explanation.textContent =
        explanations[item.ruleId] || "Review this passive signal manually.";
      card.appendChild(heading);
      card.appendChild(meta);
      card.appendChild(explanation);
      card.appendChild(evidence);
      list.appendChild(card);
    }
    refresh();
  } catch {
    renderedStates.delete(doc);
    list.replaceChildren();
    summary.textContent = "Scan unavailable";
    status.textContent =
      "Could not contact the extension. Reopen this popup or reload the tab.";
    refresh();
  }
}

if (typeof module !== "undefined") module.exports = { showPopup };
if (typeof browser !== "undefined") void showPopup(browser, document);

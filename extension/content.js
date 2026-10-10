async function createContentScanner(win, doc, api, rules) {
  async function scan() {
    const url = win.location.href;
    if (!/^https?:/.test(url)) return;
    try {
      const findings = rules.analyzeUrl(url);
      const coverage = {
        storage: "checked",
        inlineScripts: "checked",
        forms: "checked",
      };
      for (const name of ["localStorage", "sessionStorage"]) {
        try {
          const storage = win[name];
          const entries = [];
          if (storage.length > 100) coverage.storage = "partial";
          for (let i = 0; i < Math.min(storage.length, 100); i++) {
            const key = storage.key(i);
            const value = storage.getItem(key);
            if (key && value && value.length <= 2048)
              entries.push({ key, value });
            else if (value && value.length > 2048) coverage.storage = "partial";
          }
          findings.push(...rules.analyzeStorage(name, entries, url));
        } catch {
          coverage.storage = "partial"; /* Some pages deny storage access. */
        }
      }
      let total = 0;
      const scripts = Array.from(doc.querySelectorAll("script:not([src])"));
      if (scripts.length > 100) coverage.inlineScripts = "partial";
      for (const [index, script] of scripts.entries()) {
        const source = script.textContent || "";
        total += source.length;
        if (index >= 100 || total > 262144) {
          coverage.inlineScripts = "partial";
          break;
        }
        findings.push(
          ...rules.analyzeScript(
            source,
            url,
            script.id === "__NEXT_DATA__"
              ? "Next.js hydration"
              : `Inline script ${index + 1}`,
          ),
        );
      }
      const forms = Array.from(doc.querySelectorAll("form"));
      if (forms.length > 100) coverage.forms = "partial";
      for (const [index, form] of forms.slice(0, 100).entries()) {
        if (form.querySelector('input[type="password"]')) {
          findings.push(
            ...rules.analyzePasswordForm(
              form.action,
              url,
              `Password form ${index + 1}`,
            ),
          );
        }
      }
      if (findings.length)
        await api.runtime.sendMessage({ type: "findings", findings });
      await api.runtime.sendMessage({ type: "scan-complete", coverage });
    } catch {
      try {
        await api.runtime.sendMessage({ type: "scan-error" });
      } catch {
        /* The tab may be closing. */
      }
    }
  }

  api.runtime.onMessage.addListener((message) => {
    if (message?.type === "rescan") return scan();
  });
  win.setInterval(() => {
    void scan();
  }, 30000);
  await scan();
}

if (typeof module !== "undefined") module.exports = { createContentScanner };
if (typeof browser !== "undefined")
  createContentScanner(window, document, browser, ScannerRules);

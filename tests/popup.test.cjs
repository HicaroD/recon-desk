const { test } = require("node:test");
const assert = require("node:assert/strict");
const { showPopup } = require("../extension/popup.js");

function node() {
  const listeners = {};
  return {
    textContent: "",
    children: [],
    set innerHTML(_) {
      throw Error("HTML injection attempted");
    },
    appendChild(child) {
      this.children.push(child);
    },
    replaceChildren() {
      this.children = [];
    },
    addEventListener(type, fn) { listeners[type] = fn; },
    async emit(type) { await listeners[type]?.(); },
  };
}

test("popup opens the sidebar from a user action and saves a finding with its captured page context", async () => {
  const elements = { summary: node(), status: node(), findings: node(), "open-notebook": node(), "notebook-feedback": node() };
  const doc = { getElementById: id => elements[id], createElement: () => node(),
    defaultView: { crypto: require("node:crypto").webcrypto, setTimeout() {} } };
  const finding = { ruleId: "header-csp", title: "No CSP", severity: "low", confidence: "potential",
    url: "https://example.test", pagePath: "/account", evidence: "Main document response" };
  const messages = [];
  let opened = 0;
  const api = {
    tabs: { query: async () => [{ id: 8, url: "https://example.test/account?token=fixture" }] },
    sidebarAction: { open: async () => { opened++; } },
    runtime: { sendMessage: async message => {
      messages.push(message);
      return message.type === "get-scan-state" ? { status: "complete", findings: [finding] } : { note: { id: "saved" } };
    } },
  };
  await showPopup(api, doc);
  await elements["open-notebook"].emit("click");
  assert.equal(opened, 1);
  const save = elements.findings.children[0].children.find(child => child.textContent === "Save finding to note");
  assert.ok(save, "finding cards should offer a save action");
  await save.emit("click");
  const capture = messages.find(message => message.action === "capture");
  assert.equal(capture.tabId, 8);
  assert.equal(capture.url, "https://example.test/account?token=fixture");
  assert.deepEqual(capture.finding, finding);
  assert.equal(save.textContent, "Saved to notebook");
});

test("popup presents the active tab findings without injecting evidence as HTML", async () => {
  const elements = { summary: node(), status: node(), findings: node() };
  const doc = {
    getElementById: (id) => elements[id],
    createElement: () => node(),
  };
  const api = {
    tabs: { query: async () => [{ id: 5, url: "https://app.example.test/" }] },
    runtime: {
      sendMessage: async () => ({
        status: "complete",
        findings: [
          {
            ruleId: "storage-sensitive",
            severity: "medium",
            confidence: "potential",
            title: "Sensitive value in localStorage",
            url: "https://app.example.test/",
            pagePath: "/account",
            evidence: "<img src=x onerror=alert(1)>",
          },
        ],
      }),
    },
  };
  await showPopup(api, doc);
  assert.equal(elements.summary.textContent, "1 finding");
  assert.ok(JSON.stringify(elements.findings).includes("/account"));
  assert.equal(elements.findings.children.length, 1);
  assert.ok(
    JSON.stringify(elements.findings).includes("<img src=x onerror=alert(1)>"),
  );
  assert.ok(
    JSON.stringify(elements.findings).includes(
      "may be accessible to page scripts",
    ),
  );
});

test("popup distinguishes scanning, empty, failed, and unsupported pages", async () => {
  const elements = { summary: node(), status: node(), findings: node() };
  const doc = {
    getElementById: (id) => elements[id],
    createElement: () => node(),
  };
  const api = {
    tabs: { query: async () => [{ id: 5, url: "https://app.example.test/" }] },
    runtime: {
      sendMessage: async () => ({ status: "scanning", findings: [] }),
    },
  };
  await showPopup(api, doc);
  assert.equal(elements.summary.textContent, "Scanning…");
  api.runtime.sendMessage = async () => ({ status: "complete", findings: [] });
  await showPopup(api, doc);
  assert.equal(elements.summary.textContent, "No findings");
  api.runtime.sendMessage = async () => ({ status: "error", findings: [] });
  await showPopup(api, doc);
  assert.equal(elements.summary.textContent, "Scan failed");
  api.tabs.query = async () => [{ id: 5, url: "about:config" }];
  await showPopup(api, doc);
  assert.equal(elements.summary.textContent, "Page unavailable");
});

test("an open popup refreshes when a late finding arrives", async () => {
  const elements = { summary: node(), status: node(), findings: node() };
  let refresh;
  const doc = {
    getElementById: (id) => elements[id],
    createElement: () => node(),
    defaultView: {
      setTimeout: (callback) => {
        refresh = callback;
      },
    },
  };
  let findings = [];
  const api = {
    tabs: { query: async () => [{ id: 5, url: "https://app.example.test/" }] },
    runtime: { sendMessage: async () => ({ status: "complete", findings }) },
  };
  await showPopup(api, doc);
  assert.equal(elements.summary.textContent, "No findings");
  assert.equal(typeof refresh, "function");
  findings = [
    {
      ruleId: "header-csp",
      severity: "low",
      confidence: "potential",
      title: "No CSP",
      url: "https://app.example.test",
      evidence: "Main document response",
    },
  ];
  refresh();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(elements.summary.textContent, "1 finding");
});

test("findings appear while the page scan is still running", async () => {
  const elements = { summary: node(), status: node(), findings: node() };
  let refresh;
  const doc = {
    getElementById: (id) => elements[id],
    createElement: () => node(),
    defaultView: { setTimeout: (callback) => { refresh = callback; } },
  };
  let result = { status: "scanning", findings: [] };
  const api = {
    tabs: { query: async () => [{ id: 5, url: "https://app.example.test/" }] },
    runtime: { sendMessage: async () => result },
  };
  await showPopup(api, doc);
  result = {
    status: "scanning",
    findings: [{
      ruleId: "header-csp", severity: "low", confidence: "potential",
      title: "No CSP", url: "https://app.example.test", evidence: "Main document response",
    }],
  };
  refresh();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(elements.findings.children.length, 1);
  assert.equal(elements.findings.children[0].children[0].textContent, "No CSP");
  result = { ...result, status: "complete" };
  refresh();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(elements.summary.textContent, "1 finding");
});

test("polling unchanged results keeps the existing finding cards", async () => {
  const elements = { summary: node(), status: node(), findings: node() };
  let refresh;
  const doc = {
    getElementById: (id) => elements[id],
    createElement: () => node(),
    defaultView: {
      setTimeout: (callback) => {
        refresh = callback;
      },
    },
  };
  const finding = {
    ruleId: "header-csp",
    severity: "low",
    confidence: "potential",
    title: "No CSP",
    url: "https://app.example.test",
    evidence: "Main document response",
  };
  let findings = [finding];
  const api = {
    tabs: { query: async () => [{ id: 5, url: "https://app.example.test/" }] },
    runtime: { sendMessage: async () => ({ status: "complete", findings }) },
  };
  await showPopup(api, doc);
  const originalCard = elements.findings.children[0];
  refresh();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(elements.findings.children[0], originalCard);
  findings = [finding, { ...finding, ruleId: "header-hsts", title: "No HSTS" }];
  refresh();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(elements.findings.children.length, 2);
  assert.notEqual(elements.findings.children[0], originalCard);
});

test("popup explains checked and skipped sources without calling them findings", async () => {
  const elements = {
    summary: node(),
    status: node(),
    findings: node(),
    coverage: node(),
  };
  const doc = {
    getElementById: (id) => elements[id],
    createElement: () => node(),
  };
  const api = {
    tabs: { query: async () => [{ id: 5, url: "https://app.example.test/" }] },
    runtime: {
      sendMessage: async () => ({
        status: "complete",
        findings: [],
        coverage: {
          storage: "partial",
          inlineScripts: "checked",
          forms: "checked",
          headers: "checked",
          cookies: "not-inspected",
          externalScripts: "not-inspected",
        },
      }),
    },
  };
  await showPopup(api, doc);
  assert.equal(elements.summary.textContent, "No findings");
  assert.match(
    elements.coverage.textContent,
    /External scripts: not inspected/,
  );
  assert.match(elements.coverage.textContent, /Storage: partial/);
  assert.match(
    elements.coverage.textContent,
    /Checked means sampled, not exhaustive/,
  );
  assert.match(
    elements.status.textContent,
    /does not rule out vulnerabilities/,
  );
});

test("an old background response directs the user to reload the add-on", async () => {
  const elements = { summary: node(), status: node(), findings: node() };
  const doc = {
    getElementById: (id) => elements[id],
    createElement: () => node(),
  };
  const api = {
    tabs: { query: async () => [{ id: 5, url: "https://app.example.test/" }] },
    runtime: { sendMessage: async () => undefined },
  };
  await showPopup(api, doc);
  assert.equal(elements.summary.textContent, "Reload add-on");
  assert.match(elements.status.textContent, /about:debugging/);
});

test("a rejected background request points to the extension debugger", async () => {
  const elements = { summary: node(), status: node(), findings: node() };
  const doc = {
    getElementById: (id) => elements[id],
    createElement: () => node(),
  };
  const api = {
    tabs: { query: async () => [{ id: 5, url: "https://app.example.test/" }] },
    runtime: {
      sendMessage: async () => {
        throw Error("background connection failed");
      },
    },
  };
  await showPopup(api, doc);
  assert.equal(elements.summary.textContent, "Background error");
  assert.match(elements.status.textContent, /Inspect/);
});

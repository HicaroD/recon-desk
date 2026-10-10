const { test } = require("node:test");
const assert = require("node:assert/strict");
const { showPopup } = require("../extension/popup.js");

function node() {
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
  };
}

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

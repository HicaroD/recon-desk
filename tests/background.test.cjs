const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createScannerBackground } = require("../extension/background.js");
const rules = require("../extension/rules.js");

function event() {
  const listeners = [];
  return {
    addListener(listener) {
      listeners.push(listener);
    },
    async emit(...args) {
      return Promise.all(listeners.map((listener) => listener(...args)));
    },
  };
}

function fakeBrowser() {
  const data = new Map();
  const badges = [];
  return {
    data,
    badges,
    webNavigation: {
      onBeforeNavigate: event(),
      onHistoryStateUpdated: event(),
    },
    webRequest: {
      onHeadersReceived: event(),
      onBeforeRequest: event(),
      onCompleted: event(),
    },
    runtime: { onMessage: event() },
    tabs: {
      onRemoved: event(),
      get: async (id) => ({ id, url: "https://app.example.test/" }),
      sendMessage: async () => {},
    },
    cookies: { getAll: async () => [] },
    action: {
      setBadgeText: async (badge) => {
        badges.push(badge);
      },
      setBadgeBackgroundColor: async () => {},
    },
    storage: {
      local: {
        async get(key) {
          return { [key]: data.get(key) };
        },
        async set(items) {
          for (const [key, value] of Object.entries(items))
            data.set(key, value);
        },
        async remove(key) {
          data.delete(key);
        },
      },
    },
  };
}

test("badge counts deduplicated findings and resets on navigation", async () => {
  const api = fakeBrowser();
  createScannerBackground(api, rules);
  const finding = rules.analyzeStorage(
    "localStorage",
    [{ key: "auth_token", value: "secret-value-123" }],
    "https://app.example.test/",
  )[0];
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/",
  });
  await api.runtime.onMessage.emit(
    { type: "findings", findings: [finding, finding] },
    {
      tab: { id: 7, url: "https://app.example.test/" },
      url: "https://app.example.test/",
      frameId: 0,
    },
  );
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "1" });
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/next",
  });
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "" });
});

test("response headers, completed cookies, and subrequest URLs contribute to the tab", async () => {
  const api = fakeBrowser();
  api.cookies.getAll = async () => [
    { name: "session_id", secure: false, httpOnly: false },
  ];
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/",
  });
  await api.webRequest.onHeadersReceived.emit({
    tabId: 7,
    type: "main_frame",
    url: "https://app.example.test/",
    responseHeaders: [],
  });
  await api.webRequest.onCompleted.emit({
    tabId: 7,
    type: "main_frame",
    url: "https://app.example.test/",
  });
  await api.webRequest.onBeforeRequest.emit({
    tabId: 7,
    type: "xmlhttprequest",
    url: "https://api.example.test/data?access_token=secret-value-123",
  });
  const findings = (
    await api.runtime.onMessage.emit({ type: "get-findings", tabId: 7 }, {})
  )[0];
  assert.deepEqual(findings.map((item) => item.ruleId).sort(), [
    "cookie-httponly",
    "cookie-secure",
    "header-csp",
    "header-hsts",
    "url-sensitive",
  ]);
  assert.ok(!JSON.stringify(api.data).includes("secret-value-123"));
});

test("token cookie created after load is found when the popup asks for state", async () => {
  const api = fakeBrowser();
  let cookies = [];
  api.cookies.getAll = async () => cookies;
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/",
  });
  await api.webRequest.onCompleted.emit({
    tabId: 7,
    type: "main_frame",
    url: "https://app.example.test/",
  });
  cookies = [{ name: "token", httpOnly: false, secure: true }];
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.deepEqual(
    state.findings.map((item) => item.ruleId),
    ["cookie-httponly"],
  );
});

test("cookie lookup uses the active tab container", async () => {
  const api = fakeBrowser();
  api.tabs.get = async (id) => ({
    id,
    url: "https://app.example.test/",
    cookieStoreId: "firefox-container-3",
  });
  api.cookies.getAll = async (details) =>
    details.storeId === "firefox-container-3"
      ? [{ name: "token", httpOnly: false, secure: true }]
      : [];
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/",
  });
  await api.webRequest.onCompleted.emit({
    tabId: 7,
    type: "main_frame",
    url: "https://app.example.test/",
  });
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.deepEqual(
    state.findings.map((item) => item.ruleId),
    ["cookie-httponly"],
  );
});

test("tab state never stores raw path tokens", async () => {
  const api = fakeBrowser();
  createScannerBackground(api, rules);
  const token = "aVerySensitivePathToken123456";
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: `https://app.example.test/reset/${token}`,
  });
  assert.ok(!JSON.stringify([...api.data]).includes(token));
});

test("single-page navigation rescans without blocking the findings message", async () => {
  const api = fakeBrowser();
  const finding = rules.analyzeStorage(
    "localStorage",
    [{ key: "auth_token", value: "secret-value-123" }],
    "https://app.example.test/",
  )[0];
  api.tabs.sendMessage = async () =>
    api.runtime.onMessage.emit(
      { type: "findings", findings: [finding] },
      {
        tab: { id: 7, url: "https://app.example.test/" },
        url: "https://app.example.test/",
        frameId: 0,
      },
    );
  createScannerBackground(api, rules);
  await Promise.race([
    api.webNavigation.onHistoryStateUpdated.emit({
      tabId: 7,
      frameId: 0,
      url: "https://app.example.test/",
    }),
    new Promise((_, reject) =>
      setTimeout(() => reject(Error("rescan stalled")), 100),
    ),
  ]);
  await api.runtime.onMessage.emit({ type: "get-findings", tabId: 7 }, {});
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "1" });
});

test("a page is empty only after its scan completes and failures remain visible", async () => {
  const api = fakeBrowser();
  createScannerBackground(api, rules);
  const sender = {
    tab: { id: 7, url: "https://app.example.test/" },
    url: "https://app.example.test/",
    frameId: 0,
  };
  const state = async () =>
    (
      await api.runtime.onMessage.emit({ type: "get-scan-state", tabId: 7 }, {})
    )[0];
  assert.equal((await state()).status, "waiting");
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/",
  });
  assert.equal((await state()).status, "scanning");
  await api.runtime.onMessage.emit({ type: "scan-complete" }, sender);
  assert.equal((await state()).status, "complete");
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/",
  });
  await api.runtime.onMessage.emit({ type: "scan-error" }, sender);
  assert.equal((await state()).status, "error");
});

test("early header findings do not make an unfinished scan look complete", async () => {
  const api = fakeBrowser();
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/",
  });
  await api.webRequest.onHeadersReceived.emit({
    tabId: 7,
    type: "main_frame",
    url: "https://app.example.test/",
    responseHeaders: [],
  });
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.equal(state.status, "scanning");
  assert.deepEqual(state.findings.map((item) => item.ruleId).sort(), [
    "header-csp",
    "header-hsts",
  ]);
});

test("external script inspection forwards bytes unchanged and stores only redacted findings", async () => {
  const api = fakeBrowser();
  const filters = new Map();
  api.webRequest.filterResponseData = (id) => {
    const filter = {
      bytes: [],
      write(data) {
        this.bytes.push(Buffer.from(data));
      },
      disconnect() {
        this.disconnected = true;
      },
    };
    filters.set(id, filter);
    return filter;
  };
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/",
  });
  await api.webRequest.onBeforeRequest.emit({
    tabId: 7,
    type: "script",
    requestId: "script-1",
    url: "https://cdn.example.test/app.js",
  });
  const filter = filters.get("script-1");
  assert.ok(filter, "script response was not observed");
  const source = 'const privateKey = "sb_secret_123456789012";';
  const bytes = Buffer.from(source);
  filter.ondata({ data: bytes.subarray(0, 12) });
  filter.ondata({ data: bytes.subarray(12) });
  filter.onstop();
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.equal(Buffer.concat(filter.bytes).toString(), source);
  assert.equal(filter.disconnected, true);
  assert.deepEqual(
    state.findings.map((item) => item.ruleId),
    ["supabase-secret"],
  );
  assert.ok(!JSON.stringify([...api.data]).includes("sb_secret_123456789012"));
  assert.ok(!JSON.stringify([...api.data]).includes("cdn.example.test/app.js"));
});

test("popup state reports which passive sources were observed", async () => {
  const api = fakeBrowser();
  createScannerBackground(api, rules);
  const sender = {
    tab: { id: 7 },
    url: "https://app.example.test/",
    frameId: 0,
  };
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: sender.url,
  });
  await api.webRequest.onHeadersReceived.emit({
    tabId: 7,
    type: "main_frame",
    url: sender.url,
    responseHeaders: [],
  });
  await api.webRequest.onCompleted.emit({
    tabId: 7,
    type: "main_frame",
    url: sender.url,
  });
  await api.runtime.onMessage.emit(
    {
      type: "scan-complete",
      coverage: {
        storage: "partial",
        inlineScripts: "checked",
        forms: "checked",
      },
    },
    sender,
  );
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.deepEqual(state.coverage, {
    storage: "partial",
    inlineScripts: "checked",
    forms: "checked",
    headers: "checked",
    cookies: "checked",
    externalScripts: "not-inspected",
  });
});

test("unavailable response headers do not look like missing security headers", async () => {
  const api = fakeBrowser();
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/",
  });
  await api.webRequest.onHeadersReceived.emit({
    tabId: 7,
    type: "main_frame",
    url: "https://app.example.test/",
  });
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.deepEqual(state.findings, []);
  assert.equal(state.coverage.headers, "partial");
});

test("oversized external scripts pass through unchanged and are marked partial", async () => {
  const api = fakeBrowser();
  let filter;
  api.webRequest.filterResponseData = () =>
    (filter = {
      bytes: [],
      write(data) {
        this.bytes.push(Buffer.from(data));
      },
      disconnect() {},
    });
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/",
  });
  await api.webRequest.onBeforeRequest.emit({
    tabId: 7,
    type: "script",
    requestId: "large",
    url: "https://cdn.example.test/large.js",
  });
  const source = Buffer.from(`sb_secret_123456789012${"x".repeat(262144)}`);
  filter.ondata({ data: source });
  filter.onstop();
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.deepEqual(Buffer.concat(filter.bytes), source);
  assert.equal(state.coverage.externalScripts, "partial");
  assert.deepEqual(state.findings, []);
  assert.ok(!JSON.stringify([...api.data]).includes("sb_secret_123456789012"));
});

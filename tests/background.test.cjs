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
      onCommitted: event(),
      onDOMContentLoaded: event(),
      onHistoryStateUpdated: event(),
      onReferenceFragmentUpdated: event(),
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

test("badge counts deduplicated findings and resets when leaving the site", async () => {
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
    url: "https://other.example.test/next",
  });
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "" });
});

test("Firefox keeps sender.url at the original document URL after SPA navigation", async () => {
  const api = fakeBrowser();
  const original = "https://app.example.test/start";
  let url = original;
  api.tabs.get = async (id) => ({ id, url });
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  url = "https://app.example.test/next#section";
  await api.webNavigation.onHistoryStateUpdated.emit({ tabId: 7, frameId: 0, url });
  const sender = { tab: { id: 7 }, frameId: 0, url: original };
  const findings = rules.analyzeStorage("localStorage", [{ key: "auth_token", value: "fixture-token-123" }], url);
  await api.runtime.onMessage.emit({ type: "findings", pageUrl: url, findings }, sender);
  await api.runtime.onMessage.emit({ type: "scan-complete", pageUrl: url }, sender);
  assert.equal(api.data.get("tab:7").status, "complete");
  assert.equal(api.data.get("tab:7").findings[0].pagePath, "/next");
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "1" });

  // A delayed scan for the old route must not overwrite the new result.
  await api.runtime.onMessage.emit({ type: "scan-error", pageUrl: original }, sender);
  assert.equal(api.data.get("tab:7").status, "complete");
  // A document from another origin cannot claim the current route.
  await api.runtime.onMessage.emit({ type: "scan-error", pageUrl: url }, { ...sender, url: "https://other.test/" });
  assert.equal(api.data.get("tab:7").status, "complete");
});

test("findings and coverage clear on the next page of the same site", async () => {
  const api = fakeBrowser();
  let url = "https://app.example.test/first";
  api.tabs.get = async (id) => ({ id, url });
  createScannerBackground(api, rules);
  const first = rules.analyzeStorage(
    "localStorage",
    [{ key: "auth_token", value: "secret-value-123" }],
    url,
  )[0];
  const sender = () => ({ tab: { id: 7 }, url, frameId: 0 });
  const state = async () =>
    (await api.runtime.onMessage.emit({ type: "get-scan-state", tabId: 7 }, {}))[0];

  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  await api.runtime.onMessage.emit({ type: "findings", findings: [first] }, sender());
  await api.runtime.onMessage.emit(
    { type: "scan-complete", coverage: { storage: "checked" } },
    sender(),
  );
  url = "https://app.example.test/second";
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  assert.deepEqual((await state()).findings, []);
  assert.equal((await state()).status, "scanning");
  assert.equal((await state()).coverage.storage, "not-inspected");
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "" });

  const second = rules.analyzePasswordForm("http://login.example.test/", url, "Login form")[0];
  await api.runtime.onMessage.emit({ type: "findings", findings: [second] }, sender());
  await api.runtime.onMessage.emit({ type: "scan-complete", coverage: {} }, sender());
  assert.deepEqual((await state()).findings.map((item) => item.ruleId), [
    "password-form-http",
  ]);
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "1" });

  url = "https://elsewhere.example.test/";
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  assert.deepEqual((await state()).findings, []);
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "" });
});

test("revisiting a finding on another page shows only the current page path", async () => {
  const api = fakeBrowser();
  let url = "https://app.example.test/account?access_token=private-value-123";
  api.tabs.get = async (id) => ({ id, url });
  createScannerBackground(api, rules);
  const finding = rules.analyzeStorage(
    "localStorage",
    [{ key: "auth_token", value: "secret-value-123" }],
    url,
  )[0];
  for (const route of [url, "https://app.example.test/settings"]) {
    url = route;
    await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
    await api.runtime.onMessage.emit(
      { type: "findings", findings: [finding] },
      { tab: { id: 7 }, url, frameId: 0 },
    );
  }
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.deepEqual(state.findings.map((item) => item.pagePath), ["/settings"]);
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "1" });
  assert.ok(!JSON.stringify([...api.data]).includes("private-value-123"));
});

test("SPA and fragment navigation clear the previous result and reject late messages", async () => {
  const api = fakeBrowser();
  let url = "https://app.example.test/account?access_token=private-value-123";
  api.tabs.get = async (id) => ({ id, url });
  createScannerBackground(api, rules);
  const finding = rules.analyzeStorage(
    "localStorage",
    [{ key: "auth_token", value: "secret-value-123" }],
    url,
  )[0];
  const sender = (source) => ({ tab: { id: 7 }, url: source, frameId: 0 });
  const state = async () =>
    (await api.runtime.onMessage.emit({ type: "get-scan-state", tabId: 7 }, {}))[0];
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  await api.runtime.onMessage.emit({ type: "findings", findings: [finding] }, sender(url));
  const oldUrl = url;
  url = "https://app.example.test/account?access_token=other-private-value#step2";
  await api.webNavigation.onHistoryStateUpdated.emit({ tabId: 7, frameId: 0, url });
  await api.runtime.onMessage.emit({ type: "findings", findings: [finding] }, sender(oldUrl));
  await api.runtime.onMessage.emit({ type: "scan-complete", coverage: {} }, sender(oldUrl));
  assert.deepEqual((await state()).findings, []);
  assert.equal((await state()).status, "scanning");
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "" });
  assert.ok(!JSON.stringify([...api.data]).includes("other-private-value"));

  await api.runtime.onMessage.emit({ type: "findings", findings: [finding] }, sender(url));
  assert.equal((await state()).findings.length, 1);
  url = "https://app.example.test/account?access_token=other-private-value#step3";
  await api.webNavigation.onReferenceFragmentUpdated.emit({ tabId: 7, frameId: 0, url });
  assert.deepEqual((await state()).findings, []);
});

test("reloading the current URL clears its old findings before rescanning", async () => {
  const api = fakeBrowser();
  createScannerBackground(api, rules);
  const url = "https://app.example.test/account";
  const sender = { tab: { id: 7 }, url, frameId: 0 };
  const finding = rules.analyzeStorage(
    "localStorage",
    [{ key: "auth_token", value: "secret-value-123" }],
    url,
  )[0];
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  await api.runtime.onMessage.emit({ type: "findings", findings: [finding] }, sender);
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  assert.deepEqual(api.data.get("tab:7").findings, []);
  assert.equal(api.data.get("tab:7").status, "scanning");
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "" });
});

test("a redirected first visit finishes scanning the final page without a reload", async () => {
  const api = fakeBrowser();
  const requested = "https://app.example.test/start";
  const finalUrl = "https://app.example.test/dashboard";
  api.tabs.get = async (id) => ({ id, url: finalUrl });
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url: requested });
  await api.webRequest.onHeadersReceived.emit({
    tabId: 7,
    type: "main_frame",
    url: finalUrl,
    responseHeaders: [],
  });
  await api.webNavigation.onCommitted.emit({ tabId: 7, frameId: 0, url: finalUrl });
  const finding = rules.analyzeStorage(
    "localStorage",
    [{ key: "auth_token", value: "secret-value-123" }],
    finalUrl,
  )[0];
  const sender = { tab: { id: 7 }, url: finalUrl, frameId: 0 };
  await api.runtime.onMessage.emit({ type: "findings", findings: [finding] }, sender);
  await api.runtime.onMessage.emit(
    { type: "scan-complete", coverage: { storage: "checked" } },
    sender,
  );
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.equal(state.status, "complete");
  assert.deepEqual(
    state.findings.filter((item) => item.ruleId === "storage-sensitive").map((item) => item.pagePath),
    ["/dashboard"],
  );
  assert.equal(state.coverage.headers, "checked");
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "3" });
});

test("the active page's first scan recovers when navigation events miss its final URL", async () => {
  const api = fakeBrowser();
  const finalUrl = "https://app.example.test/dashboard";
  api.tabs.get = async (id) => ({ id, url: finalUrl });
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/start",
  });
  const sender = { tab: { id: 7 }, url: finalUrl, frameId: 0 };
  await api.runtime.onMessage.emit(
    { type: "scan-complete", coverage: { storage: "checked" } },
    sender,
  );
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.equal(state.status, "complete");
  assert.equal(state.coverage.storage, "checked");
  assert.ok(!JSON.stringify([...api.data]).includes("/dashboard"));
});

test("a late commit for a previous URL cannot clear the current page", async () => {
  const api = fakeBrowser();
  const currentUrl = "https://app.example.test/dashboard";
  api.tabs.get = async (id) => ({ id, url: currentUrl });
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/start",
  });
  const finding = rules.analyzeStorage(
    "localStorage",
    [{ key: "auth_token", value: "secret-value-123" }],
    currentUrl,
  )[0];
  const sender = { tab: { id: 7 }, url: currentUrl, frameId: 0 };
  await api.runtime.onMessage.emit({ type: "findings", findings: [finding] }, sender);
  await api.runtime.onMessage.emit(
    { type: "scan-complete", coverage: { storage: "checked" } },
    sender,
  );
  await api.webNavigation.onCommitted.emit({
    tabId: 7,
    frameId: 0,
    url: "https://app.example.test/start",
  });
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 },
    {},
  );
  assert.equal(state.status, "complete");
  assert.deepEqual(state.findings.map((item) => item.pagePath), ["/dashboard"]);
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
  const finding = rules.analyzeStorage(
    "localStorage",
    [{ key: "auth_token", value: "secret-value-123" }],
    `https://app.example.test/reset/${token}`,
  )[0];
  api.tabs.get = async (id) => ({ id, url: `https://app.example.test/reset/${token}` });
  await api.runtime.onMessage.emit(
    { type: "findings", findings: [finding] },
    { tab: { id: 7 }, url: `https://app.example.test/reset/${token}`, frameId: 0 },
  );
  assert.equal(api.data.get("tab:7").findings[0].pagePath, "/reset/[redacted]");
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

test("opening the popup scans an already-open page and returns its findings without a reload", async () => {
  const api = fakeBrowser();
  const url = "https://app.example.test/";
  const finding = rules.analyzeStorage(
    "localStorage", [{ key: "auth_token", value: "secret-value-123" }], url,
  )[0];
  let injected;
  const injectionFinished = new Promise((resolve) => { injected = resolve; });
  api.scripting = {
    executeScript: async ({ target, files }) => {
      assert.deepEqual(target, { tabId: 7 });
      assert.deepEqual(files, ["rules.js", "content.js"]);
      await api.runtime.onMessage.emit(
        { type: "findings", findings: [finding] },
        { tab: { id: 7 }, url, frameId: 0 },
      );
      await api.runtime.onMessage.emit(
        { type: "scan-complete", coverage: { storage: "checked" } },
        { tab: { id: 7 }, url, frameId: 0 },
      );
      injected();
    },
  };
  createScannerBackground(api, rules);
  const [first] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 }, {},
  );
  assert.equal(first.status, "scanning");
  // An injection's messages must be able to reach the background queue.
  await Promise.race([
    injectionFinished,
    new Promise((_, reject) => setTimeout(() => reject(Error("scan stalled")), 100)),
  ]);
  const [next] = await api.runtime.onMessage.emit({ type: "get-scan-state", tabId: 7 }, {});
  assert.equal(next.status, "complete");
  assert.deepEqual(next.findings.map((item) => item.ruleId), ["storage-sensitive"]);
});

test("an open popup starts a stalled navigation scan when no content script is present", async () => {
  const api = fakeBrowser();
  const url = "https://app.example.test/";
  api.tabs.sendMessage = async () => { throw Error("Receiving end does not exist"); };
  let injections = 0;
  api.scripting = { executeScript: async () => { injections++; } };
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  const state = async () => (
    await api.runtime.onMessage.emit({ type: "get-scan-state", tabId: 7 }, {})
  )[0];
  assert.equal((await state()).status, "scanning");
  assert.equal(injections, 1);
  await state();
  assert.equal(injections, 1, "polling must not keep injecting the scanner");
});

test("popup polling does not reinject when a page scanner is already attached", async () => {
  const api = fakeBrowser();
  api.tabs.sendMessage = async () => true;
  let injections = 0;
  api.scripting = { executeScript: async () => { injections++; } };
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({
    tabId: 7, frameId: 0, url: "https://app.example.test/",
  });
  const [state] = await api.runtime.onMessage.emit(
    { type: "get-scan-state", tabId: 7 }, {},
  );
  assert.equal(state.status, "scanning");
  assert.equal(injections, 0);
});

test("opening the popup retries an attached scanner whose navigation scan never finished", async () => {
  const api = fakeBrowser();
  const url = "https://app.example.test/";
  const finding = rules.analyzeStorage(
    "localStorage", [{ key: "auth_token", value: "secret-value-123" }], url,
  )[0];
  let finished;
  const scanFinished = new Promise((resolve) => { finished = resolve; });
  let retries = 0;
  api.tabs.sendMessage = async (id, message) => {
    if (message.type === "scan-presence") return true;
    if (message.type === "rescan") {
      retries++;
      await api.runtime.onMessage.emit(
        { type: "findings", findings: [finding] },
        { tab: { id }, url, frameId: 0 },
      );
      await api.runtime.onMessage.emit(
        { type: "scan-complete", coverage: { storage: "checked" } },
        { tab: { id }, url, frameId: 0 },
      );
      finished();
    }
  };
  api.scripting = { executeScript: async () => { throw Error("should not inject"); } };
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  const state = async () => (
    await api.runtime.onMessage.emit({ type: "get-scan-state", tabId: 7 }, {})
  )[0];
  assert.equal((await state()).status, "scanning");
  await Promise.race([
    scanFinished,
    new Promise((_, reject) => setTimeout(() => reject(Error("scan stalled")), 100)),
  ]);
  assert.equal((await state()).status, "complete");
  assert.deepEqual((await state()).findings.map((item) => item.ruleId), ["storage-sensitive"]);
  assert.equal(retries, 1);
});

test("navigation finishes a scan and updates the badge before opening the popup", async () => {
  const api = fakeBrowser();
  const url = "https://app.example.test/";
  const finding = rules.analyzeStorage(
    "localStorage", [{ key: "auth_token", value: "secret-value-123" }], url,
  )[0];
  api.tabs.sendMessage = async () => { throw Error("no receiver"); };
  let completed;
  const scanFinished = new Promise((resolve) => { completed = resolve; });
  api.scripting = {
    executeScript: async () => {
      await api.runtime.onMessage.emit(
        { type: "findings", findings: [finding] },
        { tab: { id: 7 }, url, frameId: 0 },
      );
      await api.runtime.onMessage.emit(
        { type: "scan-complete", coverage: { storage: "checked" } },
        { tab: { id: 7 }, url, frameId: 0 },
      );
      completed();
    },
  };
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  await api.webNavigation.onDOMContentLoaded.emit({ tabId: 7, frameId: 0, url });
  await Promise.race([
    scanFinished,
    new Promise((_, reject) => setTimeout(() => reject(Error("scan did not start")), 100)),
  ]);
  assert.equal(api.data.get("tab:7").status, "complete");
  assert.deepEqual(api.badges.at(-1), { tabId: 7, text: "1" });
});

test("navigation does not inject another scanner when the declarative script is present", async () => {
  const api = fakeBrowser();
  api.tabs.sendMessage = async () => true;
  let injections = 0;
  api.scripting = { executeScript: async () => { injections++; } };
  createScannerBackground(api, rules);
  const url = "https://app.example.test/";
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  await api.webNavigation.onDOMContentLoaded.emit({ tabId: 7, frameId: 0, url });
  assert.equal(injections, 0);
});

test("headers delivered before navigation survive commit, including fragment URLs", async () => {
  for (const fragment of ["", "#section"]) {
    const api = fakeBrowser();
    const responseUrl = "https://app.example.test/";
    const url = responseUrl + fragment;
    api.tabs.get = async (id) => ({ id, url });
    createScannerBackground(api, rules);
    await api.webRequest.onHeadersReceived.emit({
      tabId: 7, type: "main_frame", url: responseUrl, responseHeaders: [],
    });
    await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
    await api.webNavigation.onCommitted.emit({ tabId: 7, frameId: 0, url });
    assert.equal(api.data.get("tab:7").coverage.headers, "checked");
    assert.deepEqual(api.data.get("tab:7").findings.map((item) => item.ruleId).sort(), [
      "header-csp", "header-hsts",
    ]);
    // A cached restore cannot reuse an observation from a previous commit.
    await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
    await api.webNavigation.onCommitted.emit({ tabId: 7, frameId: 0, url });
    assert.equal(api.data.get("tab:7").coverage.headers, "not-inspected");
    assert.deepEqual(api.data.get("tab:7").findings, []);
  }
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

test("same-document navigation retains network observations and in-flight scripts until reload", async () => {
  const api = fakeBrowser();
  let url = "https://app.example.test/";
  api.tabs.get = async (id) => ({ id, url });
  const filters = new Map();
  api.webRequest.filterResponseData = (id) => {
    const filter = { write() {}, disconnect() {} };
    filters.set(id, filter);
    return filter;
  };
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  await api.webRequest.onHeadersReceived.emit({
    tabId: 7, type: "main_frame", url, responseHeaders: [],
  });
  const request = async (id) => {
    await api.webRequest.onBeforeRequest.emit({
      tabId: 7, type: "script", requestId: id,
      url: "https://cdn.example.test/app.js",
    });
    filters.get(id).ondata({ data: Buffer.from('const key = "sb_secret_123456789012";') });
    return filters.get(id);
  };
  await (await request("first")).onstop();
  const pending = await request("pending");
  for (const eventName of ["onHistoryStateUpdated", "onReferenceFragmentUpdated"]) {
    url = eventName === "onHistoryStateUpdated"
      ? "https://app.example.test/next" : "https://app.example.test/next#section";
    await api.webNavigation[eventName].emit({ tabId: 7, frameId: 0, url });
    const state = api.data.get("tab:7");
    assert.equal(state.coverage.headers, "checked");
    assert.equal(state.coverage.externalScripts, "checked");
    assert.equal(state.coverage.storage, "not-inspected");
    assert.deepEqual(state.findings.map((item) => item.ruleId).sort(), [
      "header-csp", "header-hsts", "supabase-secret",
    ]);
    assert.ok(state.findings.every((item) => item.pagePath === "/next"));
  }
  // A delayed script still belongs to this document after a route change.
  await pending.onstop();
  assert.equal(api.data.get("tab:7").coverage.externalScripts, "checked");
  const oldDocument = await request("old-document");
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  await oldDocument.onstop();
  assert.equal(api.data.get("tab:7").coverage.externalScripts, "not-inspected");
  assert.equal(api.data.get("tab:7").coverage.headers, "not-inspected");
  assert.deepEqual(api.data.get("tab:7").findings, []);
});

test("an in-flight script can provide the first network coverage after an SPA transition", async () => {
  const api = fakeBrowser();
  let url = "https://app.example.test/";
  api.tabs.get = async (id) => ({ id, url });
  let filter;
  api.webRequest.filterResponseData = () => (filter = { write() {}, disconnect() {} });
  createScannerBackground(api, rules);
  await api.webNavigation.onBeforeNavigate.emit({ tabId: 7, frameId: 0, url });
  await api.webRequest.onBeforeRequest.emit({
    tabId: 7, type: "script", requestId: "pending", url: "https://cdn.example.test/app.js",
  });
  url = "https://app.example.test/next";
  await api.webNavigation.onHistoryStateUpdated.emit({ tabId: 7, frameId: 0, url });
  filter.ondata({ data: Buffer.from('const key = "sb_secret_123456789012";') });
  await filter.onstop();
  assert.equal(api.data.get("tab:7").coverage.externalScripts, "checked");
  assert.equal(api.data.get("tab:7").findings[0].pagePath, "/next");
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

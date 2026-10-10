const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

test("manifest content scripts rescan a restored document without popup or interval", async () => {
  const root = path.join(__dirname, "..", "extension");
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  const messages = [];
  const listeners = new Map();
  const window = {
    location: { href: "https://example.test/?access_token=fixture-token-123" },
    localStorage: { length: 0 },
    sessionStorage: { length: 0 },
    setInterval() {}, // The regression must not wait for periodic sampling.
    addEventListener: (type, listener) => listeners.set(type, listener),
  };
  const context = vm.createContext({
    window, URL, URLSearchParams,
    document: { querySelectorAll: () => [] },
    browser: { runtime: {
      onMessage: { addListener() {} },
      sendMessage: async (message) => { messages.push(message); },
    } },
  });
  for (const name of manifest.content_scripts[0].js)
    vm.runInContext(fs.readFileSync(path.join(root, name), "utf8"), context, { filename: name });
  await new Promise(setImmediate);
  assert.deepEqual(messages.map((m) => m.type), ["findings", "scan-complete"]);
  messages.length = 0;

  assert.equal(typeof listeners.get("pageshow"), "function");
  listeners.get("pageshow")({ persisted: false });
  await new Promise(setImmediate);
  assert.equal(messages.length, 0, "ordinary pageshow must not duplicate the initial scan");

  // Firefox restores the same JS realm; neither manifest script runs again.
  listeners.get("pageshow")({ persisted: true });
  await new Promise(setImmediate);
  assert.deepEqual(messages.map((m) => m.type), ["findings", "scan-complete"]);
  assert.equal(messages[0].findings[0].ruleId, "url-sensitive");
});

test("page scanning begins after the DOM is parsed without waiting for idle loading", () => {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(__dirname, "..", "extension", "manifest.json"), "utf8"),
  );
  assert.equal(manifest.content_scripts[0].run_at, "document_end");
  assert.ok(manifest.permissions.includes("scripting"));
});

test("manifest background scripts start and answer the popup state request", async () => {
  const root = path.join(__dirname, "..", "extension");
  const manifest = JSON.parse(
    fs.readFileSync(path.join(root, "manifest.json"), "utf8"),
  );
  const handlers = [];
  const event = () => ({
    addListener(handler) {
      handlers.push(handler);
    },
  });
  const runtime = {
    onMessage: {
      addListener(handler) {
        runtime.handler = handler;
      },
    },
  };
  const api = {
    runtime,
    webNavigation: {
      onBeforeNavigate: event(),
      onCommitted: event(),
      onDOMContentLoaded: event(),
      onHistoryStateUpdated: event(),
      onReferenceFragmentUpdated: event(),
    },
    webRequest: {
      onHeadersReceived: event(),
      onCompleted: event(),
      onBeforeRequest: event(),
    },
    tabs: {
      onRemoved: event(),
      get: async (id) => ({ id, url: "https://example.test/" }),
    },
    action: { setBadgeText: async () => {} },
    storage: {
      local: {
        get: async () => ({}),
        set: async () => {},
        remove: async () => {},
      },
    },
    cookies: { getAll: async () => [] },
  };
  const context = vm.createContext({ browser: api, URL, Math });
  Object.defineProperty(context, "location", {
    configurable: false,
    enumerable: true,
    get: () => ({ href: "https://example.test/" }),
  });
  for (const name of manifest.background.scripts) {
    vm.runInContext(fs.readFileSync(path.join(root, name), "utf8"), context, {
      filename: name,
    });
  }
  assert.equal(typeof runtime.handler, "function");
  const state = await runtime.handler({ type: "get-scan-state", tabId: 5 }, {});
  assert.equal(state.status, "waiting");
  assert.deepEqual(Array.from(state.findings), []);
});

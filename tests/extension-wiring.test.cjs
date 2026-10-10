const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

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

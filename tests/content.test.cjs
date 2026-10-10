const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createContentScanner } = require("../extension/content.js");
const rules = require("../extension/rules.js");

test("page scan reports only redacted findings from storage and inline scripts", async () => {
  const messages = [];
  const win = {
    location: { href: "https://app.example.test/" },
    localStorage: {
      length: 1,
      key: () => "auth_token",
      getItem: () => "very-secret-token-123",
    },
    sessionStorage: { length: 0 },
    setInterval: () => {},
    addEventListener() {},
  };
  const doc = {
    querySelectorAll: (selector) =>
      selector === "form"
        ? []
        : [{ textContent: 'const admin = "sb_secret_123456789012";' }],
  };
  const api = {
    runtime: {
      sendMessage: async (message) => messages.push(message),
      onMessage: { addListener() {} },
    },
  };
  await createContentScanner(win, doc, api, rules);
  assert.deepEqual(
    messages.map((message) => message.type),
    ["findings", "scan-complete"],
  );
  assert.deepEqual(messages[0].findings.map((item) => item.ruleId).sort(), [
    "storage-sensitive",
    "supabase-secret",
  ]);
  assert.ok(!JSON.stringify(messages).includes("very-secret-token-123"));
  assert.ok(!JSON.stringify(messages).includes("sb_secret_123456789012"));
});

test("blocked localStorage does not prevent sessionStorage scanning", async () => {
  const messages = [];
  const win = {
    location: { href: "https://app.example.test/" },
    get localStorage() {
      throw Error("Access denied");
    },
    sessionStorage: {
      length: 1,
      key: () => "session_token",
      getItem: () => "very-secret-token-123",
    },
    setInterval: () => {},
    addEventListener() {},
  };
  const doc = { querySelectorAll: () => [] };
  const api = {
    runtime: {
      sendMessage: async (message) => messages.push(message),
      onMessage: { addListener() {} },
    },
  };
  await createContentScanner(win, doc, api, rules);
  assert.deepEqual(
    messages[0].findings.map((item) => item.ruleId),
    ["storage-sensitive"],
  );
});

test("an empty page reports completion rather than leaving the popup loading", async () => {
  const messages = [];
  const win = {
    location: { href: "https://app.example.test/" },
    localStorage: { length: 0 },
    sessionStorage: { length: 0 },
    setInterval: () => {},
    addEventListener() {},
  };
  const doc = { querySelectorAll: () => [] };
  const api = {
    runtime: {
      sendMessage: async (message) => messages.push(message),
      onMessage: { addListener() {} },
    },
  };
  await createContentScanner(win, doc, api, rules);
  assert.deepEqual(
    messages.map((message) => message.type),
    ["scan-complete"],
  );
  assert.deepEqual(messages[0].coverage, {
    storage: "checked",
    inlineScripts: "checked",
    forms: "checked",
  });
});

test("blocked storage is shown as partial scan coverage", async () => {
  const messages = [];
  const win = {
    location: { href: "https://app.example.test/" },
    get localStorage() {
      throw Error("blocked");
    },
    sessionStorage: { length: 0 },
    setInterval: () => {},
    addEventListener() {},
  };
  const doc = { querySelectorAll: () => [] };
  const api = {
    runtime: {
      sendMessage: async (message) => messages.push(message),
      onMessage: { addListener() {} },
    },
  };
  await createContentScanner(win, doc, api, rules);
  assert.equal(messages.at(-1).coverage.storage, "partial");
});

test("storage values skipped for size are marked as partial coverage", async () => {
  const messages = [];
  const win = {
    location: { href: "https://app.example.test/" },
    localStorage: {
      length: 1,
      key: () => "auth_token",
      getItem: () => "x".repeat(2049),
    },
    sessionStorage: { length: 0 },
    setInterval: () => {},
    addEventListener() {},
  };
  const doc = { querySelectorAll: () => [] };
  const api = {
    runtime: {
      sendMessage: async (message) => messages.push(message),
      onMessage: { addListener() {} },
    },
  };
  await createContentScanner(win, doc, api, rules);
  assert.equal(messages.at(-1).coverage.storage, "partial");
  assert.deepEqual(
    messages.map((message) => message.type),
    ["scan-complete"],
  );
});

test("page scan flags a password form submitted over HTTP without retaining its path", async () => {
  const messages = [];
  const win = {
    location: { href: "https://app.example.test/signin" },
    localStorage: { length: 0 },
    sessionStorage: { length: 0 },
    setInterval: () => {},
    addEventListener() {},
  };
  const form = {
    action: "http://login.example.test/private/submit?password=hidden",
    querySelector: (selector) =>
      selector === 'input[type="password"]' ? {} : null,
  };
  const doc = {
    querySelectorAll: (selector) => (selector === "form" ? [form] : []),
  };
  const api = {
    runtime: {
      sendMessage: async (message) => messages.push(message),
      onMessage: { addListener() {} },
    },
  };
  await createContentScanner(win, doc, api, rules);
  assert.deepEqual(
    messages[0].findings.map((item) => item.ruleId),
    ["password-form-http"],
  );
  assert.equal(messages[0].findings[0].url, "https://app.example.test");
  assert.ok(!JSON.stringify(messages).includes("hidden"));
});

test("Next.js hydration is identified from its script element", async () => {
  const messages = [];
  const win = {
    location: { href: "https://app.example.test/" },
    localStorage: { length: 0 },
    sessionStorage: { length: 0 },
    setInterval: () => {},
    addEventListener() {},
  };
  const script = {
    id: "__NEXT_DATA__",
    textContent:
      '{"serverRuntimeConfig":{"internalApiToken":"hidden-value-123"}}',
  };
  const doc = {
    querySelectorAll: (selector) =>
      selector === "script:not([src])" ? [script] : [],
  };
  const api = {
    runtime: {
      sendMessage: async (message) => messages.push(message),
      onMessage: { addListener() {} },
    },
  };
  await createContentScanner(win, doc, api, rules);
  assert.deepEqual(
    messages[0].findings.map((item) => item.ruleId),
    ["next-runtime-config"],
  );
  assert.ok(!JSON.stringify(messages).includes("hidden-value-123"));
});

test("a failed page scan reports an error without sending exception details", async () => {
  const messages = [];
  const win = {
    location: { href: "https://app.example.test/" },
    localStorage: { length: 0 },
    sessionStorage: { length: 0 },
    setInterval: () => {},
    addEventListener() {},
  };
  const doc = {
    querySelectorAll: () => {
      throw Error("private page data");
    },
  };
  const api = {
    runtime: {
      sendMessage: async (message) => messages.push(message),
      onMessage: { addListener() {} },
    },
  };
  await createContentScanner(win, doc, api, rules);
  assert.deepEqual(messages, [{ type: "scan-error", pageUrl: win.location.href }]);
});

test("the popup can detect an attached scanner without starting another scan", async () => {
  const messages = [];
  let onMessage;
  await createContentScanner(
    {
      location: { href: "https://app.example.test/" },
      localStorage: { length: 0 }, sessionStorage: { length: 0 },
      setInterval: () => {},
      addEventListener() {},
    },
    { querySelectorAll: () => [] },
    { runtime: {
      sendMessage: async (message) => messages.push(message),
      onMessage: { addListener: (handler) => { onMessage = handler; } },
    } },
    rules,
  );
  assert.equal(await onMessage({ type: "scan-presence" }), true);
  assert.deepEqual(messages.map((message) => message.type), ["scan-complete"]);
});

test("findings and completion retain the URL captured before a route changes", async () => {
  const pageUrl = "https://app.example.test/first?access_token=fixture-token-123";
  const win = {
    location: { href: pageUrl },
    localStorage: { length: 0 }, sessionStorage: { length: 0 },
    setInterval() {}, addEventListener() {},
  };
  const messages = [];
  await createContentScanner(win, { querySelectorAll: () => [] }, {
    runtime: {
      onMessage: { addListener() {} },
      sendMessage: async (message) => {
        messages.push(message);
        win.location.href = "https://app.example.test/second";
      },
    },
  }, rules);
  assert.deepEqual(messages.map((m) => m.type), ["findings", "scan-complete"]);
  assert.deepEqual(messages.map((m) => m.pageUrl), [pageUrl, pageUrl]);
});

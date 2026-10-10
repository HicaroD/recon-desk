const { test } = require("node:test");
const assert = require("node:assert/strict");
const rules = require("../extension/rules.js");

test("storage reports a token without retaining its value", () => {
  const value = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature";
  const findings = rules.analyzeStorage(
    "localStorage",
    [{ key: "auth_token", value }],
    "https://app.example.test/",
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "storage-sensitive");
  assert.equal(findings[0].severity, "medium");
  assert.ok(!JSON.stringify(findings).includes(value));
});

test("public client configuration is not reported as a secret", () => {
  const findings = rules.analyzeStorage(
    "localStorage",
    [
      {
        key: "supabase_anon_key",
        value: "eyJhbGciOiJIUzI1NiJ9.public.signature",
      },
      { key: "firebase_apiKey", value: "AIzaSyExamplePublicClientKey" },
    ],
    "https://app.example.test/",
  );
  assert.equal(findings.length, 0);
});

test("cookie findings apply to likely session cookies, not every preference cookie", () => {
  const cookies = [
    {
      name: "session_id",
      value: "abcdef1234567890",
      secure: false,
      httpOnly: false,
      sameSite: "no_restriction",
    },
    {
      name: "theme",
      value: "dark",
      secure: false,
      httpOnly: false,
      sameSite: "lax",
    },
  ];
  const findings = cookies.flatMap((cookie) =>
    rules.analyzeCookie(cookie, "https://app.example.test/account"),
  );
  assert.deepEqual(findings.map((item) => item.ruleId).sort(), [
    "cookie-httponly",
    "cookie-secure",
  ]);
  assert.ok(!JSON.stringify(findings).includes("abcdef1234567890"));
});

test("a document without CSP or HSTS is a review lead, not a confirmed exploit", () => {
  const findings = rules.analyzeHeaders(
    [{ name: "Content-Type", value: "text/html" }],
    "https://app.example.test/",
  );
  assert.deepEqual(findings.map((item) => item.ruleId).sort(), [
    "header-csp",
    "header-hsts",
  ]);
  assert.ok(findings.every((item) => item.confidence === "potential"));
  assert.deepEqual(
    rules
      .analyzeHeaders([], "http://app.example.test/")
      .map((item) => item.ruleId),
    ["header-csp"],
  );
});

test("inline script identifies server-only Supabase credentials but ignores public keys", () => {
  const script =
    'const publicKey = "sb_publishable_123456789012"; const admin = "sb_secret_123456789012";';
  const findings = rules.analyzeScript(
    script,
    "https://app.example.test/",
    "inline script 2",
  );
  assert.deepEqual(
    findings.map((item) => item.ruleId),
    ["supabase-secret"],
  );
  assert.equal(findings[0].confidence, "exposure");
  assert.ok(!JSON.stringify(findings).includes("sb_secret_123456789012"));
});

test("direct URL-to-HTML assignment is a potential DOM injection lead", () => {
  const findings = rules.analyzeScript(
    'document.querySelector("#result").innerHTML = window.location.hash;',
    "https://app.example.test/",
    "Inline script 1",
  );
  assert.deepEqual(
    findings.map((item) => item.ruleId),
    ["dom-location-html"],
  );
  assert.equal(findings[0].confidence, "potential");
  assert.deepEqual(
    rules.analyzeScript(
      "element.textContent = window.location.hash;",
      "https://app.example.test/",
      "Inline script 2",
    ),
    [],
  );
});

test("sensitive URL parameters are detected without copying their values into findings", () => {
  const secret = "eyJhbGciOiJIUzI1NiJ9.this-is-sensitive.signature";
  const findings = rules.analyzeUrl(
    `https://app.example.test/reset?access_token=${secret}&page=2`,
  );
  assert.deepEqual(
    findings.map((item) => item.ruleId),
    ["url-sensitive"],
  );
  assert.ok(!JSON.stringify(findings).includes(secret));
  assert.equal(findings[0].url, "https://app.example.test");
});

test("OAuth tokens in callback fragments are reported without retaining the token", () => {
  const token = "eyJhbGciOiJIUzI1NiJ9.private-payload.signature";
  const findings = rules.analyzeUrl(
    `https://app.example.test/callback#access_token=${token}&token_type=Bearer`,
  );
  assert.deepEqual(
    findings.map((item) => item.ruleId),
    ["url-fragment-token"],
  );
  assert.equal(findings[0].url, "https://app.example.test");
  assert.ok(!JSON.stringify(findings).includes(token));
  assert.deepEqual(
    rules.analyzeUrl("https://app.example.test/#/profile?tab=activity"),
    [],
  );
});

test("short path credentials are not retained in findings", () => {
  const findings = rules.analyzeUrl(
    "https://app.example.test/abcdef123456?access_token=secret-value-123",
  );
  assert.equal(findings[0].url, "https://app.example.test");
});

test("storage keys with token-like segments are redacted in evidence", () => {
  const token = "myVerySensitiveToken123456789";
  const findings = rules.analyzeStorage(
    "sessionStorage",
    [{ key: `auth_token_${token}`, value: "secret-value-123" }],
    "https://app.example.test/",
  );
  assert.equal(findings.length, 1);
  assert.ok(!JSON.stringify(findings).includes(token));
});

test("ordinary author metadata is ignored while camel-case access tokens are flagged", () => {
  const findings = rules.analyzeStorage(
    "localStorage",
    [
      { key: "author", value: "Jane Example" },
      { key: "accessToken", value: "a-secret-token-value" },
    ],
    "https://app.example.test/",
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].evidence, "localStorage key: accessToken");
});

test("server-side Supabase key in browser storage is a high-severity exposure", () => {
  const findings = rules.analyzeStorage(
    "localStorage",
    [{ key: "config", value: '{"supabase":"sb_secret_123456789012"}' }],
    "https://app.example.test/",
  );
  assert.deepEqual(
    findings.map((item) => item.ruleId),
    ["supabase-secret"],
  );
  assert.ok(!JSON.stringify(findings).includes("sb_secret_123456789012"));
});

test("legacy Supabase service-role JWT is flagged while anon JWT is ignored", () => {
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const token = `${encode({ alg: "HS256", typ: "JWT" })}.${encode({ role: "service_role", iss: "supabase" })}.signature123`;
  const anon = `${encode({ alg: "HS256" })}.${encode({ role: "anon", iss: "supabase" })}.signature123`;
  const findings = rules.analyzeStorage(
    "localStorage",
    [{ key: "client_config", value: token }],
    "https://app.example.test/",
  );
  assert.deepEqual(
    findings.map((item) => item.ruleId),
    ["supabase-service-role"],
  );
  assert.equal(findings[0].confidence, "potential");
  assert.ok(!JSON.stringify(findings).includes(token));
  assert.deepEqual(
    rules.analyzeStorage(
      "localStorage",
      [{ key: "client_config", value: anon }],
      "https://app.example.test/",
    ),
    [],
  );
});

test("Firebase service-account credentials in client code are flagged but web config is not", () => {
  const credentials = JSON.stringify({
    type: "service_account",
    project_id: "demo",
    client_email: "admin@demo.iam.gserviceaccount.com",
    private_key:
      "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----",
  });
  const findings = rules.analyzeScript(
    `const admin = ${credentials};`,
    "https://app.example.test/",
    "Inline script 1",
  );
  assert.deepEqual(
    findings.map((item) => item.ruleId),
    ["firebase-service-account"],
  );
  assert.ok(!JSON.stringify(findings).includes("admin@demo"));
  assert.deepEqual(
    rules.analyzeScript(
      'const firebaseConfig = { apiKey: "AIzaPublicConfig", projectId: "demo" };',
      "https://app.example.test/",
      "Inline script 2",
    ),
    [],
  );
});

test("Next.js hydration containing server-only runtime config is a review lead", () => {
  const source = JSON.stringify({
    props: { pageProps: {} },
    serverRuntimeConfig: { internalApiToken: "top-secret-value-123" },
  });
  const findings = rules.analyzeScript(
    source,
    "https://app.example.test/",
    "Next.js hydration",
  );
  assert.deepEqual(
    findings.map((item) => item.ruleId),
    ["next-runtime-config"],
  );
  assert.ok(!JSON.stringify(findings).includes("top-secret-value-123"));
  assert.deepEqual(
    rules.analyzeScript(
      '{"props":{"pageProps":{}},"serverRuntimeConfig":{}}',
      "https://app.example.test/",
      "Next.js hydration",
    ),
    [],
  );
});

test("React-style initial state embedding a long auth token is reported without the value", () => {
  const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature123";
  const source = `window.__INITIAL_STATE__ = {"authToken":"${token}"};`;
  const findings = rules.analyzeScript(
    source,
    "https://app.example.test/",
    "Inline script 1",
  );
  assert.deepEqual(
    findings.map((item) => item.ruleId),
    ["hydration-token"],
  );
  assert.ok(!JSON.stringify(findings).includes(token));
  assert.deepEqual(
    rules.analyzeScript(
      'window.__INITIAL_STATE__ = {"apiKey":"public-config"};',
      "https://app.example.test/",
      "Inline script 1",
    ),
    [],
  );
});

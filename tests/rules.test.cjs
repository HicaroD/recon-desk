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

test("CSP with unrestricted inline scripts is a review lead but nonce-based scripts are not", () => {
  const base = [
    { name: "Strict-Transport-Security", value: "max-age=31536000" },
  ];
  const unsafe = rules.analyzeHeaders(
    [
      ...base,
      {
        name: "Content-Security-Policy",
        value: "default-src 'self'; script-src 'self' 'unsafe-inline'",
      },
    ],
    "https://app.example.test/",
  );
  assert.deepEqual(
    unsafe.map((item) => item.ruleId),
    ["header-csp-unsafe-inline"],
  );
  assert.equal(unsafe[0].confidence, "potential");
  const nonce = rules.analyzeHeaders(
    [
      ...base,
      {
        name: "Content-Security-Policy",
        value: "script-src 'unsafe-inline' 'nonce-random123'",
      },
    ],
    "https://app.example.test/",
  );
  assert.deepEqual(nonce, []);
});

test("wildcard script sources are reviewed only when no other CSP restricts them", () => {
  const hsts = { name: "Strict-Transport-Security", value: "max-age=31536000" };
  const broad = {
    name: "Content-Security-Policy",
    value: "default-src *; img-src 'self'",
  };
  const restrictive = {
    name: "Content-Security-Policy",
    value: "script-src 'self'",
  };
  assert.deepEqual(
    rules
      .analyzeHeaders([hsts, broad], "https://app.example.test/")
      .map((item) => item.ruleId),
    ["header-csp-wildcard-script"],
  );
  assert.deepEqual(
    rules.analyzeHeaders(
      [hsts, broad, restrictive],
      "https://app.example.test/",
    ),
    [],
  );
  assert.deepEqual(
    rules.analyzeHeaders(
      [
        hsts,
        {
          name: "Content-Security-Policy",
          value: "default-src *; script-src 'self'",
        },
      ],
      "https://app.example.test/",
    ),
    [],
  );
});

test("Firefox's combined CSP header enforces each policy in the list", () => {
  const headers = (value) => [
    { name: "Strict-Transport-Security", value: "max-age=31536000" },
    { name: "Content-Security-Policy", value },
  ];
  for (const policy of [
    "script-src * 'unsafe-inline', script-src 'self'",
    "script-src 'self', script-src * 'unsafe-inline'",
    "img-src 'self', default-src 'none'",
  ]) {
    assert.deepEqual(rules.analyzeHeaders(headers(policy), "https://app.example.test/"), []);
  }
  assert.deepEqual(
    rules.analyzeHeaders(headers("img-src 'self', script-src *"), "https://app.example.test/")
      .map((item) => item.ruleId),
    ["header-csp-wildcard-script"],
  );
});

test("a CSP limited to unrelated resources does not imply script protection", () => {
  const hsts = { name: "Strict-Transport-Security", value: "max-age=31536000" };
  const policy = (value) => ({ name: "Content-Security-Policy", value });
  const ruleIds = (items) =>
    rules
      .analyzeHeaders([hsts, ...items], "https://app.example.test/")
      .map((item) => item.ruleId);
  assert.deepEqual(ruleIds([policy("img-src 'self'")]), [
    "header-csp-no-script-restriction",
  ]);
  assert.deepEqual(ruleIds([policy("")]), ["header-csp-no-script-restriction"]);
  assert.deepEqual(
    ruleIds([policy("img-src 'self'"), policy("default-src 'none'")]),
    [],
  );
  assert.deepEqual(
    ruleIds([policy("img-src 'self'"), policy("script-src *")]),
    ["header-csp-wildcard-script"],
  );
  assert.deepEqual(ruleIds([policy("sandbox")]), []);
  assert.deepEqual(
    ruleIds([policy("script-src 'nonce-example' 'strict-dynamic' *")]),
    [],
  );
});

test("HSTS with zero or invalid max-age is not treated as protection", () => {
  const csp = { name: "Content-Security-Policy", value: "default-src 'self'" };
  const check = (value) =>
    rules
      .analyzeHeaders(
        [csp, { name: "Strict-Transport-Security", value }],
        "https://app.example.test/",
      )
      .map((item) => item.ruleId);
  assert.deepEqual(check("max-age=0; includeSubDomains"), [
    "header-hsts-disabled",
  ]);
  assert.deepEqual(check('max-age="0"'), ["header-hsts-disabled"]);
  assert.deepEqual(check("max-age=abc"), ["header-hsts-disabled"]);
  assert.deepEqual(check("includeSubDomains"), ["header-hsts-disabled"]);
  assert.deepEqual(check("max-age=31536000; includeSubDomains"), []);
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

test("standalone and segmented token storage keys are reported without their values", () => {
  const findings = rules.analyzeStorage(
    "localStorage",
    [
      { key: "token", value: "private-token-value-123" },
      { key: "user_token", value: "another-private-token-123" },
      { key: "tokenizer", value: "harmless-public-setting" },
    ],
    "https://app.example.test/",
  );
  assert.deepEqual(
    findings.map((item) => item.ruleId),
    ["storage-sensitive", "storage-sensitive"],
  );
  assert.ok(!JSON.stringify(findings).includes("private-token-value-123"));
});

test("common session cookie names without token or session are reviewed", () => {
  for (const name of [
    "sid",
    "connect.sid",
    "JSESSIONID",
    "PHPSESSID",
    "ASP.NET_SessionId",
  ]) {
    assert.deepEqual(
      rules
        .analyzeCookie(
          { name, httpOnly: false, secure: true },
          "https://app.example.test/",
        )
        .map((item) => item.ruleId),
      ["cookie-httponly"],
      name,
    );
  }
  assert.deepEqual(
    rules.analyzeCookie(
      { name: "visitor_id", httpOnly: false, secure: true },
      "https://app.example.test/",
    ),
    [],
  );
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

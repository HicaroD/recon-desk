function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

function finding(
  ruleId,
  severity,
  title,
  url,
  evidence,
  confidence = "potential",
) {
  return { ruleId, severity, confidence, title, url: originOf(url), evidence };
}

function safeName(name) {
  return name.length <= 24 && /^[A-Za-z0-9_.:-]+$/.test(name)
    ? name
    : "[redacted]";
}

function hasSupabaseServiceRole(source) {
  const tokens =
    source.match(
      /[A-Za-z0-9_-]{8,256}\.[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,512}/g,
    ) || [];
  for (const token of tokens.slice(0, 20)) {
    try {
      const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      const claims = JSON.parse(atob(payload));
      if (claims.iss === "supabase" && claims.role === "service_role")
        return true;
    } catch {
      /* Not a JWT with readable claims. */
    }
  }
  return false;
}

function hasFirebaseServiceAccount(source) {
  return (
    /["']type["']\s*:\s*["']service_account["']/.test(source) &&
    /["']client_email["']\s*:/.test(source) &&
    /["']private_key["']\s*:/.test(source) &&
    /-----BEGIN PRIVATE KEY-----/.test(source)
  );
}

function analyzeStorage(area, entries, url) {
  return entries.flatMap(({ key, value }) => {
    if (typeof key !== "string" || typeof value !== "string") return [];
    if (/sb_secret_[A-Za-z0-9_-]{8,}/.test(value)) {
      return [
        finding(
          "supabase-secret",
          "high",
          "Supabase secret key in browser storage",
          url,
          `${area} key: ${safeName(key)}`,
          "exposure",
        ),
      ];
    }
    if (hasFirebaseServiceAccount(value)) {
      return [
        finding(
          "firebase-service-account",
          "high",
          "Firebase service account in browser storage",
          url,
          `${area} key: ${safeName(key)}`,
          "exposure",
        ),
      ];
    }
    if (hasSupabaseServiceRole(value)) {
      return [
        finding(
          "supabase-service-role",
          "high",
          "Supabase service-role JWT in browser storage",
          url,
          `${area} key: ${safeName(key)}`,
        ),
      ];
    }
    const normalized = key.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase();
    if (
      /(?:supabase[_-]?(?:anon|publishable)|firebase[_-]?api[_-]?key)/.test(
        normalized,
      )
    )
      return [];
    if (
      !/(?:^|[_.:-])(?:auth|access|refresh|session|bearer|jwt|token|secret|password|private)(?:$|[_.:-])/.test(
        normalized,
      )
    )
      return [];
    if (value.length < 8) return [];
    return [
      finding(
        "storage-sensitive",
        "medium",
        `Sensitive value in ${area}`,
        url,
        `${area} key: ${safeName(key)}`,
      ),
    ];
  });
}

function analyzeCookie(cookie, url) {
  if (
    !/(?:session|auth|access|refresh|token|jwt)/i.test(cookie.name || "") &&
    !/^(?:sid|connect\.sid|jsessionid|phpsessid|asp\.net_sessionid)$/i.test(
      cookie.name || "",
    )
  )
    return [];
  const evidence = `Cookie: ${safeName(cookie.name)}`;
  const results = [];
  if (!cookie.httpOnly)
    results.push(
      finding(
        "cookie-httponly",
        "medium",
        "Session cookie accessible to JavaScript",
        url,
        evidence,
      ),
    );
  if (url.startsWith("https:") && !cookie.secure)
    results.push(
      finding(
        "cookie-secure",
        "medium",
        "Session cookie can be sent without HTTPS",
        url,
        evidence,
      ),
    );
  return results;
}

function analyzeHeaders(headers, url) {
  const names = new Set(headers.map((header) => header.name.toLowerCase()));
  const results = [];
  if (!names.has("content-security-policy"))
    results.push(
      finding(
        "header-csp",
        "low",
        "No enforced Content Security Policy",
        url,
        "Main document response",
      ),
    );
  if (url.startsWith("https:") && !names.has("strict-transport-security"))
    results.push(
      finding(
        "header-hsts",
        "low",
        "No HSTS header",
        url,
        "Main document response",
      ),
    );
  const hsts = headers.filter(
    (header) => header.name.toLowerCase() === "strict-transport-security",
  );
  if (
    url.startsWith("https:") &&
    hsts.length &&
    hsts.every((header) => {
      if (typeof header.value !== "string") return false;
      const age = header.value.match(
        /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)/i,
      );
      return (
        !age || !Number.isSafeInteger(Number(age[1])) || Number(age[1]) === 0
      );
    })
  ) {
    results.push(
      finding(
        "header-hsts-disabled",
        "low",
        "HSTS header does not enable protection",
        url,
        "Main document response",
      ),
    );
  }
  const policies = headers
    .filter(
      (header) =>
        header.name.toLowerCase() === "content-security-policy" &&
        typeof header.value === "string",
    )
    // Firefox can combine multiple CSP headers into a comma-separated policy
    // list. Each policy is enforced independently, just like separate headers.
    .flatMap((header) => header.value.split(","))
    .map((policy) => {
      const directives = new Map(
        policy.split(";").map((part) => {
          const [name, ...sources] = part.trim().split(/\s+/);
          return [name.toLowerCase(), sources];
        }),
      );
      return {
        sources:
          directives.get("script-src") || directives.get("default-src") || null,
        sandboxBlocksScripts:
          directives.has("sandbox") &&
          !directives.get("sandbox").includes("allow-scripts"),
      };
    });
  if (
    policies.some(({ sources }) => sources?.includes("'unsafe-inline'")) &&
    policies.every(({ sources, sandboxBlocksScripts }) => {
      return (
        !sandboxBlocksScripts &&
        (sources === null ||
          (sources.includes("'unsafe-inline'") &&
            !sources.some((source) =>
              /^'(?:nonce-|sha(?:256|384|512)-)/.test(source),
            )))
      );
    })
  ) {
    results.push(
      finding(
        "header-csp-unsafe-inline",
        "low",
        "CSP permits unrestricted inline scripts",
        url,
        "Main document response",
      ),
    );
  }
  if (
    policies.some(({ sources }) => sources?.includes("*")) &&
    policies.every(
      ({ sources, sandboxBlocksScripts }) =>
        !sandboxBlocksScripts &&
        (sources === null ||
          (sources.includes("*") &&
            !(
              sources.includes("'strict-dynamic'") &&
              sources.some((source) =>
                /^'(?:nonce-|sha(?:256|384|512)-)/.test(source),
              )
            ))),
    )
  ) {
    results.push(
      finding(
        "header-csp-wildcard-script",
        "low",
        "CSP permits scripts from any source",
        url,
        "Main document response",
      ),
    );
  }
  if (
    policies.length &&
    policies.every(
      ({ sources, sandboxBlocksScripts }) =>
        sources === null && !sandboxBlocksScripts,
    )
  ) {
    results.push(
      finding(
        "header-csp-no-script-restriction",
        "low",
        "CSP does not restrict script sources",
        url,
        "Main document response",
      ),
    );
  }
  return results;
}

function analyzeScript(source, url, label) {
  if (typeof source !== "string") return [];
  const results = [];
  if (/sb_secret_[A-Za-z0-9_-]{8,}/.test(source)) {
    results.push(
      finding(
        "supabase-secret",
        "high",
        "Supabase secret key in browser JavaScript",
        url,
        label,
        "exposure",
      ),
    );
  }
  if (hasSupabaseServiceRole(source)) {
    results.push(
      finding(
        "supabase-service-role",
        "high",
        "Supabase service-role JWT in browser JavaScript",
        url,
        label,
      ),
    );
  }
  if (hasFirebaseServiceAccount(source)) {
    results.push(
      finding(
        "firebase-service-account",
        "high",
        "Firebase service account in browser JavaScript",
        url,
        label,
        "exposure",
      ),
    );
  } else if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(source)) {
    results.push(
      finding(
        "private-key",
        "high",
        "Private key in browser JavaScript",
        url,
        label,
        "exposure",
      ),
    );
  }
  if (
    /\.(?:innerHTML|outerHTML)\s*=\s*(?:window\.)?location\.(?:search|hash)\b/.test(
      source,
    )
  ) {
    results.push(
      finding(
        "dom-location-html",
        "medium",
        "URL content assigned directly to HTML",
        url,
        label,
      ),
    );
  }
  if (
    (label === "Next.js hydration" ||
      /(?:__INITIAL_STATE__|__PRELOADED_STATE__)/.test(source)) &&
    /["'](?:authToken|accessToken|refreshToken|idToken|sessionToken|auth_token|access_token|refresh_token)["']\s*:\s*["'][A-Za-z0-9._-]{24,}["']/.test(
      source,
    )
  ) {
    results.push(
      finding(
        "hydration-token",
        "medium",
        "Authentication token in client hydration data",
        url,
        label,
      ),
    );
  }
  if (label === "Next.js hydration") {
    try {
      const config = JSON.parse(source).serverRuntimeConfig;
      if (config && typeof config === "object" && Object.keys(config).length) {
        results.push(
          finding(
            "next-runtime-config",
            "medium",
            "Server runtime config in Next.js hydration",
            url,
            label,
          ),
        );
      }
    } catch {
      /* Not valid hydration JSON. */
    }
  }
  return results;
}
function analyzePasswordForm(action, url, label) {
  try {
    if (new URL(action || url, url).protocol === "http:") {
      return [
        finding(
          "password-form-http",
          "high",
          "Password form submits over HTTP",
          url,
          label,
        ),
      ];
    }
  } catch {
    /* Invalid form action. */
  }
  return [];
}
function analyzeUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return [];
  }
  const results = [];
  for (const [key, value] of parsed.searchParams) {
    if (
      value.length >= 8 &&
      /^(?:access_token|refresh_token|id_token|auth_token|session_token|password|secret|api[_-]?secret)$/i.test(
        key,
      )
    ) {
      results.push(
        finding(
          "url-sensitive",
          "medium",
          "Sensitive value in URL query",
          url,
          `Query parameter: ${key}`,
        ),
      );
    }
  }
  const fragment = parsed.hash.slice(1);
  const tokenParams = new URLSearchParams(
    fragment.startsWith("/") ? fragment.split("?")[1] || "" : fragment,
  );
  for (const [key, value] of tokenParams) {
    if (
      value.length >= 8 &&
      /^(?:access_token|refresh_token|id_token)$/i.test(key)
    ) {
      results.push(
        finding(
          "url-fragment-token",
          "medium",
          "OAuth token in URL fragment",
          url,
          `Fragment parameter: ${key.toLowerCase()}`,
        ),
      );
    }
  }
  return results;
}

const ScannerRules = {
  analyzeStorage,
  analyzeCookie,
  analyzeHeaders,
  analyzeScript,
  analyzePasswordForm,
  analyzeUrl,
};

if (typeof module !== "undefined") module.exports = ScannerRules;
globalThis.ScannerRules = ScannerRules;

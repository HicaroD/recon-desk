# Detection reference

ReconDesk reports **passive signals, not confirmed exploits**. **Exposure** means material was observed in browser-accessible content; **potential** means manual review is needed. Findings retain the origin, sanitized page path, and redacted evidence—not query strings, fragments, or credential values. Long, encoded, and common credential-bearing path segments are redacted.

| Rule | Detection | Significance |
| --- | --- | --- |
| `storage-sensitive` | Auth-, token-, or secret-like storage key names with values ≥8 characters; known public client-key names excluded. | Scripts could read a credential. A matching name alone does not prove sensitivity. |
| `cookie-httponly` | Session-like cookie names, including `sid` and framework session IDs, without `HttpOnly`. | Scripts can read the cookie; its session role is inferred from its name. |
| `cookie-secure` | Session-like cookies without `Secure` on HTTPS pages. | Cookies may travel over HTTP to an eligible host. |
| `header-csp` | No enforced `Content-Security-Policy` on the main response; report-only does not count. | Defense-in-depth lead, not evidence of XSS. |
| `header-csp-unsafe-inline` | Effective script directives allow `'unsafe-inline'` without a nonce/hash, accounting for other restrictive CSP headers. | Weaker injection protection; not proof of XSS. |
| `header-csp-wildcard-script` | Effective script directives allow `*` without another CSP restricting them. | Could permit scripts from untrusted origins. |
| `header-csp-no-script-restriction` | CSP lacks both `script-src` and its `default-src` fallback. | Other resource restrictions may leave scripts unconstrained. |
| `header-hsts` | No `Strict-Transport-Security` on an HTTPS main response. | Later visits may lack downgrade protection; absence alone is not an exploit. |
| `header-hsts-disabled` | HSTS lacks a valid positive `max-age`, including `max-age=0`. | Header is present but provides no upgrade protection. |
| `supabase-secret` | `sb_secret_` pattern in sampled storage or inline/observed external JavaScript. | Server credential exposed to browsers. Publishable/anon keys are excluded. |
| `supabase-service-role` | Bounded JWT candidates in storage/JavaScript claim `iss: supabase` and `role: service_role`. | A valid token could grant privileged access; claims, authenticity, and validity are unverified. |
| `firebase-service-account` | Service-account type, client email, private-key field, and PEM marker together in storage/JavaScript. | Server credential exposed. Public Firebase web configuration is excluded. |
| `private-key` | PEM private-key headers in sampled inline/observed external JavaScript, unless classified as a Firebase service account. | Could enable impersonation; authenticity and usability are unverified. |
| `dom-location-html` | Direct assignments from `location.search`/`location.hash` to `.innerHTML`/`.outerHTML` in sampled scripts. | Narrow DOM-injection heuristic, not confirmed XSS or full data-flow analysis. |
| `hydration-token` | Long values under specific auth-token names in Next.js `__NEXT_DATA__` or React-style `__INITIAL_STATE__`/`__PRELOADED_STATE__`. | Browser-readable tokens need scope/lifetime review. |
| `next-runtime-config` | Nonempty `serverRuntimeConfig` in parsed `__NEXT_DATA__`. | Possible server-only configuration exposure; properties are not assumed secret. |
| `password-form-http` | Resolved HTTP action on a form containing a password input. | Submitted passwords could travel unencrypted. |
| `url-sensitive` | Specific credential-like query parameter names with values ≥8 characters in page/observed subrequest URLs. | Values may reach history, logs, or referrers; they are not saved in findings. |
| `url-fragment-token` | Long `access_token`, `refresh_token`, or `id_token` parameters in page fragments. | Not sent in HTTP requests, but accessible to scripts and history. |

## Sampling limits

| Source | Limit |
| --- | --- |
| `localStorage` / `sessionStorage` | First 100 keys per area; 2,048 characters per value |
| Inline scripts | 100 scripts or 256 KiB total |
| Forms | 100 |
| External scripts | 20 responses per tab; 256 KiB per response |

**Checked** means sampled, not exhaustive; blocked or skipped sources appear as **partial** or **not inspected**. No active validation of backend permissions, token validity, or exploitability occurs. Public Supabase publishable/anon keys and Firebase web API keys are not vulnerabilities by themselves.

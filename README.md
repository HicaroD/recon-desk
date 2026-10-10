# Client Watcher

A Firefox extension for **automatic, passive** client-side security leads on pages you visit. It makes no validation requests, sends no findings to a server, and shows a finding count on the toolbar icon for the current tab.

## Try it in Firefox

1. Use Firefox 142 or newer. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on** and select `extension/manifest.json`.
3. Approve the requested website access, visit an HTTP or HTTPS page, and click the toolbar icon to inspect findings. Reload an already open tab after installing the extension.

Temporary add-ons are removed when Firefox restarts. The ID in the manifest is a development ID; choose a permanent one before publishing.

## Verify it is running

In a terminal from the repository root, run:

```sh
python3 -m http.server 8765 --directory fixtures
```

With the add-on loaded, open `http://127.0.0.1:8765/` in a **new** Firefox tab. The page contains fake test values. The toolbar badge should become nonempty; click it to see findings such as **Supabase secret key in browser JavaScript**, **Sensitive value in localStorage**, and **No enforced Content Security Policy**. The external script has a second fake key; its finding appears once its response has been inspected. Cookie results can depend on browser cookie settings. The exact badge count may vary. No real credentials are involved. To check URL scanning too, visit `http://127.0.0.1:8765/?access_token=fixture-token-value-123`.

On a page without matching signals, the popup says **No findings** once its scan finishes. While it is working, it says **Scanning…**. It shows **Scan failed** if page analysis throws, **Page unavailable** on protected browser pages, or **Waiting for page** if the page was already open before installing the add-on—reload that tab. Stop the local server with Ctrl+C.

If you edited extension files while Firefox was open and see **Reload add-on** or **Background error**, return to `about:debugging#/runtime/this-firefox`, click **Reload** on Client Watcher, then reload the website. A temporary add-on can otherwise keep an older background script running with a newer popup. If the error remains, click **Inspect** on the Client Watcher entry and check the first error in its console.

## Current checks

For each finding's detection method and significance, see [FINDINGS.md](FINDINGS.md).

- Session-like cookies lacking `HttpOnly` or `Secure` (cookie values are never stored).
- Token-like values in `localStorage` or `sessionStorage`, and exposed `sb_secret_` Supabase keys.
- Supabase secret keys, legacy service-role JWT claims, Firebase service-account credentials, or PEM private keys in browser storage and inline or observed external JavaScript. JWT claims are not proof that a token is valid.
- Missing or ineffective CSP/HSTS on main-document responses, reported as low-confidence review leads.
- Sensitive query parameters in the page URL and observed subrequest URLs, and OAuth tokens in page URL fragments, without retaining their values.
- Password forms submitting over HTTP and direct assignments of URL query/fragment content to HTML sinks (a heuristic review lead, not confirmed XSS).
- Nonempty Next.js `serverRuntimeConfig` in `__NEXT_DATA__` and long auth tokens in Next.js or React-style initial state.

The popup shows severity, confidence, the affected origin and page path, redacted evidence, and scan coverage by source. `Checked` means sampled, not exhaustive; `partial` means a source was blocked or exceeded a scan limit; `not inspected` means there was no observation. Findings retain a bounded, sanitized page path; long, encoded, and common credential-bearing path segments are redacted. Query strings, fragments, cookie values, storage values, and script bodies are not saved in findings. Findings are deduplicated for the current page; findings, coverage, and the badge clear when the tab navigates or reloads, including single-page route and fragment changes. The page scanner samples again every 30 seconds, and an open popup refreshes automatically. Current-page findings are stored locally so Firefox's background event page can resume. Public Supabase publishable/anon keys and Firebase web API keys are not vulnerabilities by themselves. No active checks of database rules or backend access are made.

Firefox's response filter observes up to 20 external script responses per tab and scans at most 256 KiB of each. The filter forwards the original response bytes to the page, without fetching scripts again or storing their bodies. The extension needs Firefox's `webRequestBlocking` and `webRequestFilterResponse` permissions for this. It does not confirm XSS, enumerate Firebase/Supabase access policies, scan unopened search results, or run on Firefox's protected/internal pages. Storage and inline script sampling are also bounded; missed findings and false positives are possible.

## Checks for development

```sh
npm run check
npm exec --yes --package web-ext -- web-ext lint --source-dir extension
```

The test suite uses Node's built-in test runner and has no runtime dependencies. The extension requests cookie, storage, navigation, request-metadata, HTTP/HTTPS host access, and Firefox response-filter permissions to observe pages automatically.

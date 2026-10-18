# Client Watcher

A Firefox extension for **automatic, passive** client-side security leads and a local recon notebook for websites you investigate. It makes no validation requests, sends no findings or notes to a server, and shows a finding count on the toolbar icon for the current tab.

## Try it in Firefox

1. Use Firefox 142 or newer. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on** and select `extension/manifest.json`.
3. Approve the requested website access, visit an HTTP or HTTPS page, and click the toolbar icon to inspect findings. Opening the popup starts scanning an already open eligible tab too.

Temporary add-ons are removed when Firefox restarts. The ID in the manifest is a development ID; choose a permanent one before publishing.

## Recon notebook

Open the toolbar popup and choose **Open notebook** to keep your notes beside the website in Firefox's sidebar. Reload the add-on in `about:debugging` after updating extension files.

- **Add note** creates an independent card for an observation, payload, or next step. You can keep multiple cards for each site.
- Notes belong to an exact origin: `https://example.com` shares a notebook across its pages, but `http://example.com`, `https://app.example.com`, and a different port have separate notebooks.
- Each card links to the page where it was created. The extension saves only its origin and path, without URL credentials, query parameters, or fragments. Note text is preserved as you write it, including any context you manually include.
- Text, comma-separated tags, and progress (**To investigate**, **Testing**, **Done**) save as a **draft** while you type. Wait for **Draft saved locally** before closing if you want confirmation that storage has finished. **Save note** marks the card ready; **Close editor** leaves its saved draft available through **Edit**.
- The notebook follows the active tab in its browser window. An open editor stays attached to its original site and page when you switch tabs or navigate. Its page link remains visible above the editor.
- **Edit** updates a card; **Delete** removes it. If another window changed the same card, the extension keeps your editor text and reports the conflict instead of silently overwriting the other edit. Copy any text you want to retain, close the editor, and reopen the latest card to reconcile it.
- Use the progress and tag filters to narrow the cards you see.
- **Save finding to note** in the popup captures a finding's title, severity, confidence, and already-redacted evidence. That snapshot survives navigation and scanner resets, and remains available under **Captured finding** even after you edit the note text.
- **Export Markdown** downloads the current site's complete notebook, including drafts and cards hidden by filters. Exports include page links, tags, progress, timestamps, note text, and captured evidence.

Notebook data is stored in the Firefox profile, separately from temporary scan results, and survives extension-context restarts and normal browser restarts for an installed add-on. It is not synced or uploaded. Removing the extension or its storage can remove the notebook; export research you want to keep, especially when using a temporary development add-on.

## Verify it is running

In a terminal from the repository root, run:

```sh
python3 -m http.server 8765 --directory fixtures
```

With the add-on loaded, open `http://127.0.0.1:8765/` in a **new** Firefox tab. The page contains fake test values. The toolbar badge should become nonempty; click it to see findings such as **Supabase secret key in browser JavaScript**, **Sensitive value in localStorage**, and **No enforced Content Security Policy**. The external script has a second fake key; its finding appears once its response has been inspected. Cookie results can depend on browser cookie settings. The exact badge count may vary. No real credentials are involved. To check URL scanning too, visit `http://127.0.0.1:8765/?access_token=fixture-token-value-123`.

On a page without matching signals, the popup says **No findings** once its scan finishes. While it is working, it says **Scanning…**. It shows **Scan failed** if page analysis throws, **Page unavailable** on protected browser pages, or **Waiting for page** if Firefox has not granted page access. Opening the popup also starts a scan on an eligible tab that was already open when the add-on was loaded. Stop the local server with Ctrl+C.

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

The popup shows severity, confidence, the affected origin and page path, redacted evidence, and scan coverage by source. `Checked` means sampled, not exhaustive; `partial` means a source was blocked or exceeded a scan limit; `not inspected` means there was no observation. Findings retain a bounded, sanitized page path; long, encoded, and common credential-bearing path segments are redacted. Query strings, fragments, cookie values, storage values, and script bodies are not saved in findings. Findings are deduplicated for the current page; findings, coverage, and the badge clear on a new document or reload. Single-page route and fragment changes retain the document's header and external-script observations while rescanning page-local sources. The page scanner samples again every 30 seconds, and an open popup refreshes automatically. Current-page findings are stored locally so Firefox's background event page can resume. Public Supabase publishable/anon keys and Firebase web API keys are not vulnerabilities by themselves. No active checks of database rules or backend access are made.

Headers and external scripts are inspected as network responses arrive. If a page was already loaded before the add-on started, reload the website to capture these sources. Opening the popup or waiting for a periodic scan cannot replay earlier network responses. Pages without external script requests can legitimately show external scripts as `not inspected`.

Firefox's response filter observes up to 20 external script responses per tab and scans at most 256 KiB of each. The filter forwards the original response bytes to the page, without fetching scripts again or storing their bodies. The extension needs Firefox's `webRequestBlocking` and `webRequestFilterResponse` permissions for this. It does not confirm XSS, enumerate Firebase/Supabase access policies, scan unopened search results, or run on Firefox's protected/internal pages. Storage and inline script sampling are also bounded; missed findings and false positives are possible.

## Checks for development

```sh
npm run check
npm exec --yes --package web-ext -- web-ext lint --source-dir extension
```

The test suite uses Node's built-in test runner and has no runtime dependencies. The extension requests cookie, storage, navigation, request-metadata, HTTP/HTTPS host access, and Firefox response-filter permissions to observe pages automatically.

### Real Firefox smoke tests

With Firefox, Python 3, Selenium 4 (`python3 -m pip install selenium`), and `openssl` available:

```sh
python3 tests/firefox_smoke.py
# If Firefox is not discoverable, for example on macOS:
python3 tests/firefox_smoke.py --firefox /Applications/Firefox.app/Contents/MacOS/firefox
# Notebook interactions, persistence, export, and opening the native sidebar:
python3 tests/notebook_firefox.py --firefox /Applications/Firefox.app/Contents/MacOS/firefox
```

This launches an isolated Firefox profile, temporarily installs a copy of the extension, and serves local HTTP and self-signed HTTPS fixtures. Selenium Manager resolves geckodriver. It checks initial navigation, cached Back/Forward, reload, SPA and fragment navigation, and clearing the badge on a clean page. It also asserts checked header/external-script coverage on network loads and its retention across same-document navigation. It reads persisted state and the real toolbar badge without opening the popup or sending a scan request. Completion must occur within five seconds, before the 30-second sampling interval can mask a failure. The Back/Forward cases assert that Firefox actually restored the cached document.

The suite also runs 40 synthetic detection cases covering all 19 rule IDs in `tests/firefox_fixtures.py`. It checks exact rule/evidence pairs, source coverage, the toolbar badge, and redaction of fixture credentials. Storage cases cover both storage areas, and JavaScript cases cover inline and real external responses. Cases include cookies, CSP/HSTS variants, hydration, password forms, page/subrequest queries, and OAuth fragments. Negative controls check public client configuration, protected cookies, safe forms/sinks, and restrictive CSP policies. A rule-inventory assertion fails if a new rule lacks a Firefox fixture. These cases exercise the supported detection patterns, not every possible vulnerability or encoding.

Two Firefox lifecycle details matter: cached documents resume through `pageshow` (`persisted: true`), without rerunning content scripts or `DOMContentLoaded`; and message `sender.url` can remain the original document URL after a same-document navigation. The scanner rescans restored documents and includes its captured page URL in messages, which the background validates against the sender origin and current tab. That raw URL is not persisted. Cached restores do not replay network observations, so header/external-script coverage can remain `not inspected`.

The notebook Firefox suite drives the unmodified sidebar document in an extension tab while a fixture remains the browser's active tab, because WebDriver cannot directly address native sidebar content. It checks draft recovery after document reload, safe payload rendering, tags/progress, cross-origin tab switching during an edit, real Markdown downloads, finding capture through the real popup document, opening the native sidebar from a click, and persistence after reinstalling the same temporary add-on. The optional `--screenshot /absolute/path.png` flag captures the native sidebar. Node tests additionally cover concurrent writes, stale-edit conflicts, delayed autosaves after deletion, storage failures, and extension-only notebook messaging.

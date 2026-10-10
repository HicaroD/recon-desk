function createScannerBackground(api, rules) {
  const states = new Map();
  const queues = new Map();
  const scriptCounts = new Map();
  const key = (id) => `tab:${id}`;
  const emptyCoverage = () => ({
    storage: "not-inspected",
    inlineScripts: "not-inspected",
    forms: "not-inspected",
    headers: "not-inspected",
    cookies: "not-inspected",
    externalScripts: "not-inspected",
  });
  const page = (url) => {
    try {
      return new URL(url).origin;
    } catch {
      return "";
    }
  };

  function enqueue(id, work) {
    const next = (queues.get(id) || Promise.resolve())
      .catch(() => {})
      .then(work);
    queues.set(id, next);
    void next.then(
      () => {
        if (queues.get(id) === next) queues.delete(id);
      },
      () => {
        if (queues.get(id) === next) queues.delete(id);
      },
    );
    return next;
  }

  async function load(id) {
    if (states.has(id)) return states.get(id);
    const stored = (await api.storage.local.get(key(id)))[key(id)];
    const state = stored || {
      url: "",
      status: "waiting",
      findings: [],
      coverage: emptyCoverage(),
    };
    states.set(id, state);
    return state;
  }

  async function save(id, state) {
    states.set(id, state);
    await api.storage.local.set({ [key(id)]: state });
    await api.action.setBadgeText({
      tabId: id,
      text: state.findings.length
        ? String(Math.min(99, state.findings.length))
        : "",
    });
  }

  async function reset(id, url) {
    const state = await load(id);
    const sameSite = state.url === page(url);
    if (!sameSite) scriptCounts.delete(id);
    await save(id, {
      url: page(url),
      status: "scanning",
      findings: sameSite ? state.findings : [],
      coverage: sameSite ? state.coverage : emptyCoverage(),
    });
  }

  async function markCoverage(id, url, name, value) {
    const state = await load(id);
    if (state.url !== page(url)) return;
    const previous = state.coverage?.[name];
    if (previous === "partial" || previous === value) return;
    await save(id, {
      ...state,
      coverage: { ...emptyCoverage(), ...state.coverage, [name]: value },
    });
  }

  async function markScriptCoverage(id, owner, value) {
    const url = await owner;
    if (url) await markCoverage(id, url, "externalScripts", value);
  }

  async function add(id, url, findings) {
    const state = await load(id);
    if (state.url && state.url !== page(url)) return;
    const next = {
      ...state,
      url: state.url || page(url),
      findings: [...state.findings],
    };
    const seen = new Set(
      next.findings.map(
        (item) => `${item.ruleId}:${item.url}:${item.evidence}`,
      ),
    );
    for (const item of findings) {
      if (
        !item ||
        typeof item.ruleId !== "string" ||
        typeof item.evidence !== "string" ||
        !/^https?:/.test(item.url || "")
      )
        continue;
      const identity = `${item.ruleId}:${item.url}:${item.evidence}`;
      if (!seen.has(identity) && next.findings.length < 100) {
        next.findings.push(item);
        seen.add(identity);
      }
    }
    if (next.findings.length !== state.findings.length) await save(id, next);
  }

  async function scanCookies(id, url, tab) {
    if ((await load(id)).url !== page(url)) return;
    try {
      const activeTab = tab || (await api.tabs.get(id));
      const details = { url };
      if (activeTab.cookieStoreId) details.storeId = activeTab.cookieStoreId;
      const cookies = await api.cookies.getAll(details);
      await add(
        id,
        url,
        cookies.flatMap((cookie) => rules.analyzeCookie(cookie, url)),
      );
      await markCoverage(id, url, "cookies", "checked");
    } catch {
      await markCoverage(id, url, "cookies", "partial");
    }
  }

  api.webNavigation.onBeforeNavigate.addListener(({ tabId, frameId, url }) => {
    if (tabId >= 0 && frameId === 0)
      return enqueue(tabId, () => reset(tabId, url));
  });
  api.webNavigation.onHistoryStateUpdated.addListener(
    ({ tabId, frameId, url }) => {
      if (tabId >= 0 && frameId === 0)
        return enqueue(tabId, () => reset(tabId, url)).then(() => {
          void api.tabs.sendMessage(tabId, { type: "rescan" }).catch(() => {});
        });
    },
  );
  api.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (
        details.tabId < 0 ||
        details.type !== "main_frame" ||
        !/^https?:/.test(details.url)
      )
        return;
      return enqueue(details.tabId, async () => {
        if (Array.isArray(details.responseHeaders)) {
          await add(
            details.tabId,
            details.url,
            rules.analyzeHeaders(details.responseHeaders, details.url),
          );
        }
        await markCoverage(
          details.tabId,
          details.url,
          "headers",
          Array.isArray(details.responseHeaders) ? "checked" : "partial",
        );
      });
    },
    { urls: ["<all_urls>"], types: ["main_frame"] },
    ["responseHeaders"],
  );
  api.webRequest.onCompleted.addListener(
    (details) => {
      if (
        details.tabId < 0 ||
        details.type !== "main_frame" ||
        !/^https?:/.test(details.url)
      )
        return;
      return enqueue(details.tabId, async () => {
        await scanCookies(details.tabId, details.url);
      });
    },
    { urls: ["<all_urls>"], types: ["main_frame"] },
  );
  api.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (
        details.tabId < 0 ||
        details.type === "main_frame" ||
        !/^https?:/.test(details.url)
      )
        return;
      const owner =
        details.type === "script"
          ? api.tabs
              .get(details.tabId)
              .then((tab) => tab.url)
              .catch(() => "")
          : null;
      if (
        details.type === "script" &&
        details.requestId &&
        api.webRequest.filterResponseData
      ) {
        const count = scriptCounts.get(details.tabId) || 0;
        if (count < 20) {
          try {
            const filter = api.webRequest.filterResponseData(details.requestId);
            scriptCounts.set(details.tabId, count + 1);
            const chunks = [];
            let size = 0;
            filter.ondata = (event) => {
              filter.write(event.data);
              if (size + event.data.byteLength > 262144) {
                size = 262145;
                chunks.length = 0;
              } else if (size <= 262144) {
                chunks.push(event.data.slice(0));
                size += event.data.byteLength;
              }
            };
            filter.onstop = () => {
              filter.disconnect();
              if (size > 262144)
                return enqueue(details.tabId, () =>
                  markScriptCoverage(details.tabId, owner, "partial"),
                );
              const bytes = new Uint8Array(size);
              let offset = 0;
              for (const chunk of chunks) {
                bytes.set(new Uint8Array(chunk), offset);
                offset += chunk.byteLength;
              }
              const findings = rules.analyzeScript(
                new TextDecoder().decode(bytes),
                details.url,
                "External script",
              );
              return enqueue(details.tabId, async () => {
                const originalUrl = await owner;
                const tab = await api.tabs.get(details.tabId);
                if (!originalUrl || page(tab.url) !== page(originalUrl)) return;
                if (findings.length)
                  await add(details.tabId, originalUrl, findings);
                await markScriptCoverage(details.tabId, owner, "checked");
              });
            };
            filter.onerror = () => {
              try {
                filter.disconnect();
              } catch {
                /* Request ended. */
              }
              void enqueue(details.tabId, () =>
                markScriptCoverage(details.tabId, owner, "partial"),
              );
            };
          } catch {
            void enqueue(details.tabId, () =>
              markScriptCoverage(details.tabId, owner, "partial"),
            );
          }
        } else {
          void enqueue(details.tabId, () =>
            markScriptCoverage(details.tabId, owner, "partial"),
          );
        }
      } else if (details.type === "script") {
        void enqueue(details.tabId, () =>
          markScriptCoverage(details.tabId, owner, "partial"),
        );
      }
      const findings = rules.analyzeUrl(details.url);
      if (!findings.length) return;
      return enqueue(details.tabId, async () => {
        const tab = await api.tabs.get(details.tabId);
        await add(details.tabId, tab.url, findings);
      });
    },
    { urls: ["<all_urls>"] },
    ["blocking"],
  );
  api.runtime.onMessage.addListener((message, sender) => {
    if (message?.type === "get-scan-state") {
      return enqueue(message.tabId, async () => {
        const tab = await api.tabs.get(message.tabId);
        const state = await load(message.tabId);
        if (!state.url || state.url !== page(tab.url))
          return { status: "waiting", findings: [], coverage: emptyCoverage() };
        await scanCookies(message.tabId, tab.url, tab);
        const current = await load(message.tabId);
        return {
          status: current.status || "waiting",
          findings: current.findings,
          coverage: { ...emptyCoverage(), ...current.coverage },
        };
      });
    }
    if (message?.type === "get-findings") {
      return enqueue(message.tabId, async () => {
        const tab = await api.tabs.get(message.tabId);
        const state = await load(message.tabId);
        return state.url === page(tab.url) ? state.findings : [];
      });
    }
    if (
      !["findings", "scan-complete", "scan-error"].includes(message?.type) ||
      !sender.tab ||
      sender.frameId !== 0
    )
      return;
    return enqueue(sender.tab.id, async () => {
      const tab = await api.tabs.get(sender.tab.id);
      if (page(tab.url) !== page(sender.url)) return;
      if (message.type === "findings") {
        if (Array.isArray(message.findings))
          await add(sender.tab.id, sender.url, message.findings);
        return;
      }
      const state = await load(sender.tab.id);
      if (state.url !== page(sender.url)) return;
      const coverage = { ...emptyCoverage(), ...state.coverage };
      if (message.type === "scan-complete") {
        for (const name of ["storage", "inlineScripts", "forms"]) {
          if (["checked", "partial"].includes(message.coverage?.[name]))
            coverage[name] = message.coverage[name];
        }
      }
      await save(sender.tab.id, {
        ...state,
        coverage,
        status: message.type === "scan-error" ? "error" : "complete",
      });
      if (message.type === "scan-complete")
        await scanCookies(sender.tab.id, sender.url, tab);
    });
  });
  api.tabs.onRemoved.addListener((id) =>
    enqueue(id, async () => {
      states.delete(id);
      scriptCounts.delete(id);
      await api.storage.local.remove(key(id));
    }),
  );
}

if (typeof module !== "undefined") module.exports = { createScannerBackground };
if (typeof browser !== "undefined")
  createScannerBackground(browser, ScannerRules);

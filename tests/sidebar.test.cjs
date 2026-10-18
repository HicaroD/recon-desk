const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createNotebook } = require("../extension/notebook.js");
const { startSidebar } = require("../extension/sidebar.js");

function event() {
  const listeners = [];
  return { addListener: fn => listeners.push(fn), emit: async (...args) => {
    await Promise.all(listeners.map(fn => fn(...args)));
  } };
}

function element(tagName = "div") {
  const listeners = {};
  return {
    tagName, textContent: "", value: "", children: [], hidden: false, disabled: false,
    set innerHTML(_) { throw Error("HTML injection attempted"); },
    appendChild(child) { this.children.push(child); return child; },
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    setAttribute(name, value) { this[name] = value; },
    addEventListener(name, listener) { (listeners[name] ||= []).push(listener); },
    async emit(name) { for (const fn of listeners[name] || []) await fn({ preventDefault() {} }); },
    focus() {},
  };
}

function setup() {
  const data = {};
  const notebook = createNotebook({
    async get(key) { return structuredClone({ [key]: data[key] }); },
    async set(items) { Object.assign(data, structuredClone(items)); },
  });
  let tab = { id: 1, windowId: 4, url: "https://example.test/account?token=omit" };
  const api = {
    windows: { getCurrent: async () => ({ id: 4 }) },
    tabs: { query: async () => [tab], onActivated: event(), onUpdated: event(), create: async () => {} },
    storage: { onChanged: event() },
    runtime: { sendMessage: async message => {
      try { return await notebook.request(message); } catch (error) { return { error: error.message }; }
    } },
  };
  const ids = ["site", "notebook-status", "notes", "add-note", "export-notes", "filter-progress", "filter-tag",
    "editor", "editor-source", "note-text", "note-tags", "note-progress", "save-note", "close-editor", "editor-status"];
  const elements = Object.fromEntries(ids.map(id => [id, element()]));
  const doc = { getElementById: id => elements[id], createElement: tag => element(tag),
    defaultView: { crypto: require("node:crypto").webcrypto, confirm: () => true } };
  return { api, doc, elements, notebook, setTab: next => { tab = next; } };
}

function find(root, text) {
  if (root.textContent === text) return root;
  for (const child of root.children || []) {
    const found = find(child, text);
    if (found) return found;
  }
}

test("sidebar shows independent cards safely and follows the active site in its own window", async () => {
  const { api, doc, elements, notebook, setTab } = setup();
  await notebook.request({ action: "save", url: "https://example.test/one", revision: 0,
    note: { id: "one", text: "<img src=x onerror=alert(1)>", tags: ["auth"], progress: "Testing" } });
  await notebook.request({ action: "save", url: "https://example.test/two", revision: 0,
    note: { id: "two", text: "Another lead" } });
  await startSidebar(api, doc);
  assert.equal(elements.site.textContent, "https://example.test");
  assert.equal(elements.notes.children.length, 2);
  assert.ok(JSON.stringify(elements.notes).includes("<img src=x onerror=alert(1)>"));
  elements["filter-progress"].value = "Testing";
  await elements["filter-progress"].emit("change");
  assert.equal(elements.notes.children.length, 1);
  setTab({ id: 2, windowId: 4, url: "https://other.test/" });
  await api.tabs.onActivated.emit({ windowId: 4, tabId: 2 });
  assert.equal(elements.site.textContent, "https://other.test");
  assert.match(elements["notebook-status"].textContent, /No notes/);
  setTab({ id: 3, windowId: 4, url: "about:config" });
  await api.tabs.onActivated.emit({ windowId: 4, tabId: 3 });
  assert.equal(elements["add-note"].disabled, true);
});

test("a tab switch cannot create a note for the previous site while the new notebook loads", async () => {
  const { api, doc, elements, setTab } = setup();
  await startSidebar(api, doc);
  const send = api.runtime.sendMessage;
  let release;
  api.runtime.sendMessage = message => message.action === "list" && message.url === "https://other.test/"
    ? new Promise(resolve => { release = async () => resolve(await send(message)); }) : send(message);
  setTab({ id: 2, windowId: 4, url: "https://other.test/" });
  const switching = api.tabs.onActivated.emit({ windowId: 4, tabId: 2 });
  await new Promise(setImmediate);
  const adding = elements["add-note"].emit("click");
  assert.equal(elements.editor.hidden, true, "the old site's context must not remain actionable");
  await release();
  await switching;
  await adding;
  assert.equal(elements.site.textContent, "https://other.test");
});

test("draft typing survives closing the sidebar and remains pinned when the active tab changes", async () => {
  const { api, doc, elements, notebook, setTab } = setup();
  await startSidebar(api, doc);
  await elements["add-note"].emit("click");
  assert.equal(elements.editor.hidden, false);
  elements["note-text"].value = "Test another user's invoice\n```http\nGET /invoice/2\n```";
  await elements["note-text"].emit("input");
  const draft = (await notebook.request({ action: "list", url: "https://example.test/" })).notes[0];
  assert.equal(draft?.text, elements["note-text"].value, "typing must persist before Save note is clicked");
  assert.equal(draft.draft, true);
  setTab({ id: 2, windowId: 4, url: "https://other.test/elsewhere" });
  await api.tabs.onActivated.emit({ windowId: 4, tabId: 2 });
  assert.equal(elements["editor-source"].textContent, "https://example.test/account");
  elements["note-tags"].value = "auth, idor";
  elements["note-progress"].value = "Testing";
  await elements["save-note"].emit("click");
  assert.equal(elements.editor.hidden, true);
  const note = await notebook.request({ action: "list", url: "https://other.test/" });
  assert.equal(note.notes.length, 0);
  const saved = (await notebook.request({ action: "list", url: "https://example.test/" })).notes[0];
  assert.equal(saved.draft, false);
  assert.deepEqual(saved.tags, ["auth", "idor"]);
  assert.equal(saved.progress, "Testing");
});

test("cards can be edited and deleted without losing a sibling note", async () => {
  const { api, doc, elements, notebook } = setup();
  const url = "https://example.test/";
  for (const id of ["one", "two"])
    await notebook.request({ action: "save", url, revision: 0, note: { id, text: id } });
  await startSidebar(api, doc);
  const edit = find(elements.notes.children[0], "Edit");
  assert.ok(edit, "each card needs an Edit action");
  await edit.emit("click");
  elements["note-text"].value = "Updated observation";
  await elements["save-note"].emit("click");
  assert.ok(find(elements.notes, "Updated observation"));
  await find(elements.notes.children[0], "Delete").emit("click");
  const { notes } = await notebook.request({ action: "list", url });
  assert.equal(notes.length, 1);
  assert.equal(notes[0].text, "one");
});

test("failed autosave keeps the editor text and can be retried", async () => {
  const { api, doc, elements, notebook } = setup();
  await startSidebar(api, doc);
  await elements["add-note"].emit("click");
  const send = api.runtime.sendMessage;
  api.runtime.sendMessage = async () => ({ error: "Storage full" });
  elements["note-text"].value = "Do not lose this research";
  await elements["note-text"].emit("input");
  assert.match(elements["editor-status"].textContent, /Not saved: Storage full/);
  assert.equal(elements["note-text"].value, "Do not lose this research");
  assert.equal(elements.editor.hidden, false);
  api.runtime.sendMessage = send;
  await elements["save-note"].emit("click");
  assert.equal((await notebook.request({ action: "list", url: "https://example.test/" })).notes[0].text, "Do not lose this research");
});

test("typing dispatches the latest draft before prior replies so closing cannot abandon a local save queue", async () => {
  const { api, doc, elements } = setup();
  await startSidebar(api, doc);
  await elements["add-note"].emit("click");
  const send = api.runtime.sendMessage;
  const saves = [], replies = [];
  api.runtime.sendMessage = message => {
    if (message.action !== "save") return send(message);
    saves.push(message);
    return new Promise(resolve => replies.push(async () => resolve(await send(message))));
  };
  elements["note-text"].value = "F";
  const first = elements["note-text"].emit("input");
  elements["note-text"].value = "Full research";
  const last = elements["note-text"].emit("input");
  await new Promise(setImmediate);
  assert.equal(saves.length, 2, "all draft messages must leave the sidebar before earlier responses arrive");
  await replies[0]();
  await first;
  assert.equal(elements["editor-status"].textContent, "Saving…", "an older reply must not claim the latest text is saved");
  await replies[1]();
  await last;
  assert.equal(elements["editor-status"].textContent, "Draft saved locally");
});

test("export downloads the full site notebook even when the visible cards are filtered", async () => {
  const { api, doc, elements, notebook } = setup();
  const url = "https://example.test/";
  await notebook.request({ action: "save", url, revision: 0, note: { id: "one", text: "Unfiltered research" } });
  let blob, download;
  doc.defaultView.Blob = Blob;
  doc.defaultView.URL = { createObjectURL: value => { blob = value; return "blob:test"; }, revokeObjectURL() {} };
  doc.defaultView.setTimeout = fn => fn();
  const create = doc.createElement;
  doc.createElement = tag => {
    const node = create(tag);
    if (tag === "a") node.click = () => { download = { filename: node.download, href: node.href }; };
    return node;
  };
  await startSidebar(api, doc);
  elements["filter-progress"].value = "Done";
  await elements["filter-progress"].emit("change");
  await elements["export-notes"].emit("click");
  assert.ok(download, "Export must initiate a browser download");
  assert.match(download.filename, /example.test.*\.md$/);
  assert.equal(blob.type, "text/markdown;charset=utf-8");
  assert.match(await blob.text(), /Unfiltered research/);
});

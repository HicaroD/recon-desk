const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createNotebook } = require("../extension/notebook.js");

function storage() {
  const data = {};
  return {
    async get(key) { return structuredClone({ [key]: data[key] }); },
    async set(items) { Object.assign(data, structuredClone(items)); },
  };
}

test("separate note cards persist across notebook restarts and pages of the same origin", async () => {
  const local = storage();
  const notebook = createNotebook(local);
  await notebook.request({ action: "save", url: "https://user:pass@example.test/account?token=secret#oauth", note: {
    id: "first", text: "Test account ownership\n<img src=x onerror=alert(1)>", tags: ["auth"], progress: "Testing", draft: false,
  }, revision: 0 });
  await notebook.request({ action: "save", url: "https://example.test/uploads", note: {
    id: "second", text: "Inspect upload types", draft: false,
  }, revision: 0 });
  const restarted = createNotebook(local);
  const { notes } = await restarted.request({ action: "list", url: "https://example.test/other" });
  assert.equal(notes.length, 2);
  const first = notes.find(n => n.id === "first");
  assert.equal(first.sourceUrl, "https://example.test/account");
  assert.equal(first.text, "Test account ownership\n<img src=x onerror=alert(1)>");
  assert.deepEqual(first.tags, ["auth"]);
  assert.equal(first.progress, "Testing");
  assert.equal(first.revision, 1);
  assert.ok(first.createdAt && first.updatedAt);
  for (const url of ["https://sub.example.test/account", "http://example.test/account", "https://example.test:8443/"])
    assert.deepEqual((await restarted.request({ action: "list", url })).notes, []);
});

test("Markdown export includes all site notes, drafts, metadata and intact multiline payloads", async () => {
  const notebook = createNotebook(storage());
  const url = "https://example.test/test?secret=omit";
  const text = "Try this payload:\n```html\n<img src=x onerror=alert(1)>\n```\nThen compare roles.";
  await notebook.request({ action: "save", url, revision: 0,
    note: { id: "one", text, tags: ["auth", "api"], progress: "Testing", draft: false } });
  await notebook.request({ action: "save", url, revision: 0,
    note: { id: "two", text: "Unfinished thought", draft: true } });
  const result = await notebook.request({ action: "export", url });
  assert.equal(typeof result.markdown, "string", "export should return a Markdown document");
  assert.match(result.filename, /example.test.*\.md$/);
  assert.ok(result.markdown.includes(text));
  assert.match(result.markdown, /Source: <https:\/\/example.test\/test>/);
  assert.match(result.markdown, /Progress: Testing/);
  assert.match(result.markdown, /Tags: auth, api/);
  assert.match(result.markdown, /Created: \d{4}-/);
  assert.match(result.markdown, /Updated: \d{4}-/);
  assert.match(result.markdown, /Draft/);
  assert.match(result.markdown, /Unfinished thought/);
  assert.ok(!result.markdown.includes("secret=omit"));
});

test("a captured finding keeps redacted evidence and metadata after its editable text changes", async () => {
  const local = storage();
  const notebook = createNotebook(local);
  const url = "https://example.test/account?access_token=never-store#token";
  const finding = { ruleId: "storage-sensitive", title: "Sensitive value in localStorage",
    severity: "medium", confidence: "potential", evidence: "auth_token: [redacted]", url: "https://example.test", pagePath: "/account" };
  const captured = await notebook.request({ action: "capture", url, id: "snapshot", finding });
  assert.ok(captured.note, "capture should produce a persistent note");
  assert.equal(captured.note.text, "Sensitive value in localStorage\n\nauth_token: [redacted]");
  assert.equal(captured.note.snapshot.confidence, "potential");
  await notebook.request({ action: "save", url, revision: 1,
    note: { ...captured.note, text: "Reviewed this lead", snapshot: { evidence: "tampered" } } });
  const note = (await createNotebook(local).request({ action: "list", url })).notes[0];
  assert.equal(note.snapshot.evidence, "auth_token: [redacted]");
  assert.equal(note.sourceUrl, "https://example.test/account");
  assert.ok(!JSON.stringify(note).includes("never-store"));
});

test("invalid notes and failed writes do not erase saved research or poison later operations", async () => {
  const local = storage();
  const notebook = createNotebook(local);
  const request = { action: "save", url: "https://example.test/", revision: 0,
    note: { id: "valid", text: "Keep me" } };
  await notebook.request(request);
  await assert.rejects(notebook.request({ ...request, note: { id: "invalid", text: "", progress: "Unknown" } }), /note|progress/i);
  const write = local.set;
  local.set = async () => { throw Error("Storage full"); };
  await assert.rejects(notebook.request({ ...request, note: { id: "other", text: "Not saved" } }), /Storage full/);
  local.set = write;
  assert.equal((await notebook.request({ action: "list", url: request.url })).notes.length, 1);
  await assert.rejects(notebook.request({ action: "list", url: "file:///tmp/test" }), /HTTP/);
});

test("simultaneous windows retain both new notes and reject conflicting edits", async () => {
  const notebook = createNotebook(storage());
  const url = "https://example.test/";
  const save = (id, text, revision = 0) => notebook.request({ action: "save", url,
    revision, note: { id, text } });
  await Promise.all([save("one", "First window"), save("two", "Second window")]);
  assert.equal((await notebook.request({ action: "list", url })).notes.length, 2);
  const results = await Promise.allSettled([save("one", "Edit A", 1), save("one", "Edit B", 1)]);
  assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
  assert.equal(results.filter(r => r.status === "rejected").length, 1);
});

test("in-flight draft updates from one editor persist in order without waiting for previous replies", async () => {
  const notebook = createNotebook(storage());
  const url = "https://example.test/";
  const save = (text, sequence) => notebook.request({ action: "save", url, revision: 0,
    edit: { id: "editor-one", sequence }, note: { id: "draft", text, draft: true } });
  await Promise.all([save("F", 1), save("Full research", 2)]);
  const { notes } = await notebook.request({ action: "list", url });
  assert.equal(notes[0].text, "Full research");
  await assert.rejects(save("Late old event", 1), /changed|newer/i);
  await notebook.request({ action: "save", url, revision: notes[0].revision,
    note: { id: "draft", text: "Other window's edit", draft: false } });
  await assert.rejects(save("Old editor cannot overwrite", 3), /changed/i);
});

test("a delayed autosave from a new editor cannot recreate a deleted note", async () => {
  const notebook = createNotebook(storage());
  const url = "https://example.test/";
  const save = sequence => notebook.request({ action: "save", url, revision: 0,
    edit: { id: "new-editor", sequence }, note: { id: "deleted-draft", text: "Draft", draft: true } });
  await save(1);
  await notebook.request({ action: "delete", url, id: "deleted-draft", revision: 1 });
  await assert.rejects(save(2), /changed|deleted/i);
  assert.deepEqual((await notebook.request({ action: "list", url })).notes, []);
});

test("draft edits keep their original source and stale edits cannot overwrite or resurrect notes", async () => {
  const local = storage();
  const notebook = createNotebook(local);
  const url = "https://example.test/original";
  let { note } = await notebook.request({ action: "save", url, revision: 0,
    note: { id: "draft", text: "Unfinished", draft: true } });
  assert.equal((await createNotebook(local).request({ action: "list", url })).notes[0].draft, true);
  const created = note.createdAt;
  ({ note } = await notebook.request({ action: "save", url: "https://example.test/elsewhere", revision: 1,
    note: { ...note, text: "Finished", tags: ["auth", "auth", " api "], progress: "Done", draft: false } }));
  assert.equal(note.sourceUrl, url);
  assert.equal(note.createdAt, created);
  assert.equal(note.revision, 2);
  assert.deepEqual(note.tags, ["auth", "api"]);
  await assert.rejects(notebook.request({ action: "save", url, revision: 1,
    note: { ...note, text: "Stale edit" } }), /changed in another window/);
  await notebook.request({ action: "delete", url, id: note.id, revision: 2 });
  assert.deepEqual((await notebook.request({ action: "list", url })).notes, []);
  await assert.rejects(notebook.request({ action: "save", url, revision: 2, note }), /changed|deleted/);
});

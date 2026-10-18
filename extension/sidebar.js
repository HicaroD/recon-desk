async function startSidebar(api, doc) {
  const get = id => doc.getElementById(id);
  const { id: windowId } = await api.windows.getCurrent();
  let current, notes = [], refreshId = 0, editing;
  get("editor").hidden = true;
  const request = async message => {
    const result = await api.runtime.sendMessage({ type: "notebook-request", ...message });
    if (!result || result.error) throw Error(result?.error || "Notebook unavailable. Reload the extension and try again.");
    return result;
  };
  function node(tag, text, className) {
    const element = doc.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  }
  function openEditor(note, url) {
    editing = { note, url, baseRevision: note.revision, id: doc.defaultView.crypto.randomUUID(), sequence: 0, queue: Promise.resolve(true) };
    get("editor").hidden = false;
    get("editor-source").textContent = note.sourceUrl;
    get("note-text").value = note.text;
    get("note-tags").value = note.tags.join(", ");
    get("note-progress").value = note.progress;
    get("editor-status").textContent = note.draft ? "Draft saved locally" : "Changes save as a draft while you type.";
    get("add-note").disabled = true;
    get("note-text").focus();
  }
  function persist(draft) {
    const session = editing;
    if (!session) return Promise.resolve(false);
    const values = { id: session.note.id, text: get("note-text").value,
      tags: get("note-tags").value.split(",").map(tag => tag.trim()).filter(Boolean),
      progress: get("note-progress").value, draft };
    const sequence = ++session.sequence;
    get("editor-status").textContent = "Saving…";
    // Dispatch immediately. A sidebar can disappear before earlier responses
    // arrive; the background owns the write queue and edit ordering.
    session.queue = request({ action: "save", url: session.url, note: values, revision: session.baseRevision,
      edit: { id: session.id, sequence } }).then(async result => {
        if (result.note.revision > session.note.revision) session.note = result.note;
        if (editing === session && sequence === session.sequence)
          get("editor-status").textContent = draft ? "Draft saved locally" : "Note saved locally";
        await refresh();
        return true;
      }).catch(error => {
        if (editing === session && sequence === session.sequence) get("editor-status").textContent = `Not saved: ${error.message}`;
        return false;
      });
    return session.queue;
  }
  function render() {
    const visible = notes.filter(note =>
      (!get("filter-progress").value || note.progress === get("filter-progress").value) &&
      (!get("filter-tag").value || note.tags.some(tag => tag.toLowerCase().includes(get("filter-tag").value.trim().toLowerCase()))));
    get("notes").replaceChildren();
    for (const note of [...visible].reverse()) {
      const card = node("article", undefined, "note-card");
      card.append(node("p", `${note.draft ? "Draft · " : ""}${note.progress}`, "note-state"));
      card.append(node("p", note.text || "Empty draft", "note-body"));
      const source = node("a", note.sourceUrl, "note-source");
      source.href = note.sourceUrl;
      source.target = "_blank";
      source.rel = "noopener noreferrer";
      card.append(source);
      if (note.tags.length) card.append(node("p", note.tags.map(tag => `#${tag}`).join(" "), "note-tags"));
      card.append(node("p", `Created ${new Date(note.createdAt).toLocaleString()} · Updated ${new Date(note.updatedAt).toLocaleString()}`, "note-time"));
      if (note.snapshot) {
        const evidence = node("details");
        evidence.append(node("summary", "Captured finding"),
          node("p", `${note.snapshot.title} · ${note.snapshot.severity} · ${note.snapshot.confidence}`),
          node("pre", note.snapshot.evidence));
        card.append(evidence);
      }
      const actions = node("div", undefined, "card-actions");
      const edit = node("button", "Edit");
      edit.type = "button";
      edit.disabled = !!editing;
      edit.addEventListener("click", () => {
        if (!editing) {
          openEditor(note, note.sourceUrl);
          render();
        }
      });
      const remove = node("button", "Delete", "danger");
      remove.type = "button";
      remove.disabled = editing?.note.id === note.id;
      remove.addEventListener("click", async () => {
        if (!doc.defaultView.confirm("Delete this note permanently?")) return;
        remove.disabled = true;
        try {
          await request({ action: "delete", url: note.sourceUrl, id: note.id, revision: note.revision });
          await refresh();
        } catch (error) {
          get("notebook-status").textContent = error.message;
          remove.disabled = false;
        }
      });
      actions.append(edit, remove);
      card.append(actions);
      get("notes").append(card);
    }
    get("notebook-status").textContent = !notes.length ? "No notes yet. Add your first observation." :
      `${visible.length} of ${notes.length} notes`;
  }
  async function refresh() {
    const generation = ++refreshId;
    current = undefined;
    get("add-note").disabled = get("export-notes").disabled = true;
    try {
      const [tab] = await api.tabs.query({ active: true, windowId });
      if (generation !== refreshId) return;
      if (!/^https?:/.test(tab?.url || "")) {
        current = undefined;
        notes = [];
        get("site").textContent = "Choose a website";
        get("notes").replaceChildren();
        get("add-note").disabled = get("export-notes").disabled = true;
        get("notebook-status").textContent = "Open an HTTP or HTTPS page to use its notebook.";
        return;
      }
      const result = await request({ action: "list", url: tab.url });
      if (generation !== refreshId) return;
      current = { url: tab.url, origin: result.origin, tabId: tab.id };
      notes = result.notes;
      get("site").textContent = result.origin;
      get("add-note").disabled = !!editing;
      get("export-notes").disabled = false;
      render();
    } catch (error) {
      if (generation === refreshId) {
        current = undefined;
        notes = [];
        get("notes").replaceChildren();
        get("site").textContent = "Notebook unavailable";
        get("add-note").disabled = get("export-notes").disabled = true;
        get("notebook-status").textContent = error.message;
      }
    }
  }
  get("filter-progress").addEventListener("change", render);
  get("filter-tag").addEventListener("input", render);
  get("add-note").addEventListener("click", async () => {
    if (!current || editing) return;
    const url = new URL(current.url);
    openEditor({ id: doc.defaultView.crypto.randomUUID(), text: "", tags: [], progress: "To investigate",
      revision: 0, draft: true, sourceUrl: url.origin + url.pathname }, current.url);
    await persist(true);
  });
  for (const id of ["note-text", "note-tags", "note-progress"])
    get(id).addEventListener(id === "note-progress" ? "change" : "input", () => persist(true));
  get("save-note").addEventListener("click", async () => {
    if (!editing) return;
    const session = editing;
    const controls = ["note-text", "note-tags", "note-progress", "save-note", "close-editor"];
    controls.forEach(id => { get(id).disabled = true; });
    if (await persist(false) && editing === session) {
      editing = undefined;
      get("editor").hidden = true;
      await refresh();
    }
    controls.forEach(id => { get(id).disabled = false; });
  });
  get("close-editor").addEventListener("click", async () => {
    if (!editing) return;
    if (!await editing.queue && !doc.defaultView.confirm("This edit could not be saved. Close the editor and discard unsaved changes?")) return;
    editing = undefined;
    get("editor").hidden = true;
    await refresh();
  });
  get("export-notes").addEventListener("click", async () => {
    if (!current) return;
    const url = current.url;
    try {
      if (editing && !await editing.queue) throw Error("Save or close the unsaved edit before exporting.");
      const result = await request({ action: "export", url });
      const win = doc.defaultView;
      const objectUrl = win.URL.createObjectURL(new win.Blob([result.markdown], { type: "text/markdown;charset=utf-8" }));
      const link = node("a");
      link.href = objectUrl;
      link.download = result.filename;
      link.click();
      win.setTimeout(() => win.URL.revokeObjectURL(objectUrl), 1000);
      get("notebook-status").textContent = "Notebook exported as Markdown.";
    } catch (error) {
      get("notebook-status").textContent = error.message;
    }
  });
  api.tabs.onActivated.addListener(info => info.windowId === windowId ? refresh() : undefined);
  api.tabs.onUpdated.addListener((_id, change, tab) =>
    tab.windowId === windowId && tab.active && change.url ? refresh() : undefined);
  api.storage.onChanged.addListener((changes, area) =>
    area === "local" && current && changes[`notebook:v1:${current.origin}`] ? refresh() : undefined);
  await refresh();
}

if (typeof module !== "undefined") module.exports = { startSidebar };
if (typeof browser !== "undefined") void startSidebar(browser, document);

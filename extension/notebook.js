const NOTE_PROGRESS = ["To investigate", "Testing", "Done"];

function notebookMarkdown(origin, notes) {
  const metadata = value => String(value).replace(/[\r\n]/g, " ").replace(/([\\`*_[\]<>#])/g, "\\$1");
  const literal = value => {
    const runs = String(value).match(/`+/g) || [];
    const fence = "`".repeat(Math.max(3, ...runs.map(run => run.length + 1)));
    return `${fence}text\n${value}\n${fence}`;
  };
  return `# Recon notebook — ${origin}\n\n` + notes.map((note, index) => {
    const snapshot = note.snapshot;
    return `## Note ${index + 1}${note.draft ? " (Draft)" : ""}\n\n` +
      `Source: <${note.sourceUrl}>\n\nProgress: ${note.progress}\n\n` +
      `Tags: ${note.tags.map(metadata).join(", ") || "None"}\n\n` +
      `Created: ${note.createdAt}\n\nUpdated: ${note.updatedAt}\n\n${note.text}\n\n` +
      (snapshot ? `### Captured finding\n\n${metadata(snapshot.title)}\n\n` +
        `Severity: ${metadata(snapshot.severity)} · Confidence: ${metadata(snapshot.confidence)}\n\n` +
        `Rule: ${metadata(snapshot.ruleId)}\n\n${literal(snapshot.evidence)}\n\n` : "");
  }).join("---\n\n");
}

function createNotebook(local) {
  // One background instance is the writer for all extension windows. Reads join
  // the same queue so a refresh cannot overtake a pending save.
  let queue = Promise.resolve();
  async function perform({ action, url, note, id = note?.id, revision, finding, edit }) {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) throw Error("Choose an HTTP or HTTPS page.");
    const origin = parsed.origin;
    const key = `notebook:v1:${origin}`;
    const book = (await local.get(key))[key] || { version: 1, notes: [] };
    if (book.version !== 1 || !Array.isArray(book.notes))
      throw Error("Unsupported notebook data. Existing research was not changed.");
    if (action === "list") return { origin, notes: book.notes };
    if (action === "export") return {
      filename: `recon-${parsed.host.replace(/[^\w.-]/g, "-")}.md`,
      markdown: notebookMarkdown(origin, book.notes),
    };
    let snapshot;
    if (action === "capture") {
      snapshot = Object.fromEntries(["ruleId", "title", "severity", "confidence", "evidence"].map(field => [field, finding[field]]));
      note = { id, text: `${snapshot.title}\n\n${snapshot.evidence}`, draft: false };
      revision = 0;
      action = "save";
    }
    if (typeof id !== "string" || !/^[\w-]{1,100}$/.test(id) || !Number.isInteger(revision) || revision < 0)
      throw Error("Invalid note identity or revision.");
    if (edit && (typeof edit.id !== "string" || !/^[\w-]{1,100}$/.test(edit.id) ||
        !Number.isInteger(edit.sequence) || edit.sequence < 1)) throw Error("Invalid note editor.");
    const previous = book.notes.find(item => item.id === id);
    if (book.deleted?.includes(id)) throw Error("This note was deleted in another window.");
    const continuingEdit = action === "save" && edit && previous?.edit?.id === edit.id &&
      previous.edit.baseRevision === revision && edit.sequence > previous.edit.sequence;
    if ((previous?.revision || 0) !== revision && !continuingEdit)
      throw Error("This note changed in another window. Reopen it before saving.");
    if (action === "delete") {
      book.notes = book.notes.filter(item => item.id !== id);
      // Keep only the retired identity, never its text or evidence, so delayed
      // first-editor autosaves cannot resurrect deleted research.
      book.deleted = [...(book.deleted || []), id];
      await local.set({ [key]: book });
      return { deleted: id };
    }
    if (action === "save") {
      if (typeof note?.text !== "string" || note.text.length > 100000 || (!note.draft && !note.text.trim()))
        throw Error("A note needs text (up to 100,000 characters).");
      if (note.progress !== undefined && !NOTE_PROGRESS.includes(note.progress))
        throw Error("Invalid note progress.");
      if (note.tags !== undefined && (!Array.isArray(note.tags) || note.tags.length > 50 ||
          note.tags.some(tag => typeof tag !== "string" || tag.length > 100)))
        throw Error("Use up to 50 tags, each up to 100 characters.");
      const now = new Date().toISOString();
      const saved = {
        id, text: note.text, tags: [...new Set((note.tags || []).map(tag => tag.trim()).filter(Boolean))],
        progress: note.progress || "To investigate", draft: !!note.draft,
        sourceUrl: previous?.sourceUrl || origin + parsed.pathname,
        createdAt: previous?.createdAt || now, updatedAt: now, revision: (previous?.revision || 0) + 1,
        ...(edit ? { edit: { ...edit, baseRevision: revision } } : {}),
        ...((previous?.snapshot || snapshot) ? { snapshot: previous?.snapshot || snapshot } : {}),
      };
      book.notes = [...book.notes.filter(item => item.id !== id), saved];
      await local.set({ [key]: book });
      return { note: saved };
    }
    throw Error("Unknown notebook action.");
  }
  return {
    request(message) {
      const result = queue.then(() => perform(message));
      queue = result.catch(() => {});
      return result;
    },
  };
}

const ReconNotebook = { createNotebook, NOTE_PROGRESS };
if (typeof module !== "undefined") module.exports = ReconNotebook;

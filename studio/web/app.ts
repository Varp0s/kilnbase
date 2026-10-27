// Studio UI. Rows written by end users are shown on a page that holds the service_role key, so
// everything is rendered with textContent / DOM APIs; innerHTML is never used.

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Row = Record<string, Json>;

const KEY = "kilnbase-studio-key";
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const view = $<HTMLElement>("view");

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function text(value: Json | undefined): string {
  if (value === null || value === undefined) return "null";
  return typeof value === "string" ? value : JSON.stringify(value);
}

function table(rows: Row[], columns?: string[]): HTMLElement {
  if (rows.length === 0) return el("p", { className: "hint" }, "No rows.");
  const cols = columns ?? Object.keys(rows[0] ?? {});
  const head = el("tr", {}, ...cols.map((c) => el("th", {}, c)));
  const body = rows.map((r) => el("tr", {}, ...cols.map((c) => el("td", {}, el("code", {}, text(r[c]))))));
  return el("div", { className: "scroll" }, el("table", {}, el("thead", {}, head), el("tbody", {}, ...body)));
}

class SignedOut extends Error {}

/** Raw requests for file bodies; same key handling as api(). */
async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const res = await fetch(path, {
    ...init,
    headers: { Authorization: `Bearer ${sessionStorage.getItem(KEY) ?? ""}`, ...(init.headers ?? {}) },
  });
  if (res.status === 401) throw new SignedOut();
  if (!res.ok) {
    const data = (await res.json().catch(() => ({}))) as { message?: string };
    throw new Error(data.message ?? `HTTP ${res.status}`);
  }
  return res;
}

function size(bytes: number | null): string {
  if (bytes === null) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let n = bytes, i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : n} ${units[i]}`;
}

async function api<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      Authorization: `Bearer ${sessionStorage.getItem(KEY) ?? ""}`,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) throw new SignedOut();
  const data = (await res.json()) as T & { message?: string };
  if (!res.ok) throw new Error(data.message ?? `HTTP ${res.status}`);
  return data;
}

interface Policy { name: string; command: string; roles: string[]; using: string | null; check: string | null }
interface TableInfo { name: string; rls: boolean; policies: Policy[] }
interface User {
  id: string; email: string | null; created_at: string; is_anonymous: boolean;
  email_confirmed_at: string | null; last_sign_in_at: string | null; active_sessions: number;
}
interface ViewAsResult { role: string; claims: Row; denied: boolean; rows: Row[] }
interface Column { name: string; type: string; nullable: boolean; default: string | null; primary_key: boolean; read_only: boolean }
interface RowsPage { columns: Column[]; key: string[]; rows: Row[] }
interface Bucket { id: string; public: boolean; objects: number; bytes: number; created_at: string }
interface StoredObject { name: string; size: number | null; mime_type: string | null; updated_at: string; folder: boolean }
interface Webhook {
  name: string; table: string; events: string[]; enabled: boolean; host: string;
  pending: number; failed: number; created_at: string;
}
interface Delivery { id: number; webhook: string; status: string; attempts: number; last_status: number | null; last_error: string | null; created_at: string }
interface Extension { name: string; default_version: string; installed_version: string | null; comment: string | null; schema: string | null }
interface DatabaseInfo {
  version: string; bytes: number; connections: number; max_connections: number; tables: number;
  started_at: string; extensions: Extension[];
}
interface SqlResult { columns: string[]; rows: Json[][]; truncated: boolean; status: string; committed: boolean }

const PAGE = 50;

/** Inputs hold text; JSON and array columns are parsed, everything else is cast by Postgres. */
function parseInput(column: Column, raw: string): Json {
  return /(\[\]|json|jsonb)$/.test(column.type) ? (JSON.parse(raw) as Json) : raw;
}

/** One table's rows, a page at a time, with add / edit / delete where it has a primary key. */
function dataEditor(name: string): HTMLElement {
  const box = el("div");
  let offset = 0;

  const write = (action: string, body: unknown) =>
    api<{ row: Row }>(`/api/tables/${encodeURIComponent(name)}/rows?action=${action}`, body);

  function rowForm(page: RowsPage, row: Row | null): HTMLFormElement {
    const inputs = new Map<string, HTMLInputElement>();
    const fields = page.columns.map((c) => {
      const input = el("input", {
        value: row ? text(row[c.name]) : "",
        placeholder: row ? "" : (c.default ?? (c.nullable ? "null" : "required")),
        disabled: c.read_only,
      });
      inputs.set(c.name, input);
      return el("label", { className: "field" }, el("span", {}, `${c.name} `, el("small", {}, c.type)), input);
    });
    const message = el("p", { className: "hint" });
    const cancel = el("button", { type: "button" }, "Cancel");
    cancel.addEventListener("click", () => void render());
    const form = el("form", { className: "row-form" }, ...fields,
      el("button", { type: "submit" }, row ? "Save" : "Insert"), cancel, message);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const values: Record<string, Json> = {};
      try {
        for (const c of page.columns) {
          const input = inputs.get(c.name)!;
          if (c.read_only) continue;
          if (row === null) {
            if (input.value !== "") values[c.name] = parseInput(c, input.value);
          } else if (input.value !== text(row[c.name])) {
            // A cleared field means NULL; untouched fields are not sent.
            values[c.name] = input.value === "" ? null : parseInput(c, input.value);
          }
        }
      } catch (err) {
        message.textContent = `Not valid JSON: ${err instanceof Error ? err.message : String(err)}`;
        return;
      }
      if (row !== null && Object.keys(values).length === 0) return void render();
      const key = row === null ? undefined : Object.fromEntries(page.key.map((k) => [k, row[k] ?? null]));
      write(row === null ? "insert" : "update", { key, values })
        .then(() => render())
        .catch((err: unknown) => fail(err, message));
    });
    return form;
  }

  async function render(): Promise<void> {
    box.replaceChildren(el("p", { className: "hint" }, "Loading…"));
    try {
      const page = await api<RowsPage>(`/api/tables/${encodeURIComponent(name)}/rows?offset=${offset}&limit=${PAGE}`);
      const editable = page.key.length > 0;
      const cols = page.columns.map((c) => c.name);
      const head = el("tr", {}, ...cols.map((c) => el("th", {}, c)), editable ? el("th", {}) : "");
      const body = page.rows.map((r) => {
        const cells = cols.map((c) => el("td", {}, el("code", {}, text(r[c]))));
        if (!editable) return el("tr", {}, ...cells);
        const editBtn = el("button", { type: "button" }, "Edit");
        const delBtn = el("button", { type: "button", className: "danger" }, "Delete");
        editBtn.addEventListener("click", () => box.replaceChildren(el("h3", {}, "Edit row"), rowForm(page, r)));
        delBtn.addEventListener("click", () => {
          if (!confirm("Delete this row? This cannot be undone.")) return;
          const key = Object.fromEntries(page.key.map((k) => [k, r[k] ?? null]));
          write("delete", { key }).then(() => render()).catch((err: unknown) => fail(err, box));
        });
        return el("tr", {}, ...cells, el("td", { className: "actions" }, editBtn, delBtn));
      });
      const prev = el("button", { type: "button", disabled: offset === 0 }, "← Previous");
      const next = el("button", { type: "button", disabled: page.rows.length < PAGE }, "Next →");
      prev.addEventListener("click", () => { offset = Math.max(0, offset - PAGE); void render(); });
      next.addEventListener("click", () => { offset += PAGE; void render(); });
      const add = el("button", { type: "button", disabled: !editable }, "Add row");
      add.addEventListener("click", () => box.replaceChildren(el("h3", {}, "New row"), rowForm(page, null)));
      box.replaceChildren(
        el("div", { className: "toolbar" }, add, prev, next,
          el("span", { className: "hint" }, page.rows.length ? `Rows ${offset + 1}–${offset + page.rows.length}` : "")),
        editable ? "" : el("p", { className: "hint" }, "No primary key: rows are read-only here."),
        page.rows.length
          ? el("div", { className: "scroll" }, el("table", {}, el("thead", {}, head), el("tbody", {}, ...body)))
          : el("p", { className: "hint" }, "No rows."));
    } catch (err) {
      fail(err, box);
    }
  }

  void render();
  return box;
}

/** Opens the SQL editor with `sql` filled in; nothing runs until the admin presses Run. */
function draftSql(sql: string): void {
  sessionStorage.setItem("kilnbase-studio-sql", sql);
  void show("sql");
}

function quoteIdent(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

function copyButton(value: string): HTMLButtonElement {
  const b = el("button", { type: "button", className: "small" }, "Copy");
  b.addEventListener("click", () => {
    void navigator.clipboard.writeText(value).then(() => { b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy"; }, 1500); });
  });
  return b;
}

const views: Record<string, () => Promise<Node[]>> = {
  async tables() {
    const tables = await api<TableInfo[]>("/api/tables");
    return tables.flatMap((t) => [
      el("h2", {}, `public.${t.name} `,
        el("span", { className: t.rls ? "ok" : "error" }, t.rls ? "RLS on" : "RLS off: hidden from the API"), " ",
        (() => {
          const table = `public.${quoteIdent(t.name)}`;
          const b = el("button", { type: "button", className: "small" }, t.rls ? "Add policy" : "Enable RLS");
          b.addEventListener("click", () => draftSql(t.rls
            ? `-- Who may see or change which rows. Review, then Run.\ncreate policy "own rows" on ${table}\n  for all to authenticated\n  using (owner = auth.uid())\n  with check (owner = auth.uid());\n`
            : `-- With RLS on, the table appears in the API; add policies to decide who sees which rows.\nalter table ${table} enable row level security;\n`));
          return b;
        })()),
      t.policies.length
        ? table(t.policies.map((p) => ({ ...p, roles: p.roles.join(", ") })), ["name", "command", "roles", "using", "check"])
        : el("p", { className: "hint" }, t.rls ? "No policies: nobody can read it through the API." : ""),
    ]);
  },

  async data() {
    const tables = await api<TableInfo[]>("/api/tables");
    if (tables.length === 0) return [el("p", { className: "hint" }, "No tables in public yet.")];
    const select = el("select", { id: "data-table" }, ...tables.map((t) => el("option", { value: t.name }, t.name)));
    const holder = el("div", {}, dataEditor(tables[0]!.name));
    select.addEventListener("change", () => holder.replaceChildren(dataEditor(select.value)));
    return [
      el("p", { className: "hint" }, "Edits run as service_role, so row level security does not apply. Values are cast by Postgres; JSON and array columns take JSON."),
      el("form", {}, el("label", { htmlFor: "data-table" }, "Table"), select),
      holder,
    ];
  },

  async sql() {
    const query = el("textarea", { id: "sql-query", rows: 10, spellcheck: false, placeholder: "select * from public.todos limit 10;" });
    query.value = sessionStorage.getItem("kilnbase-studio-sql") ?? "";
    const rollback = el("input", { type: "checkbox", id: "sql-rollback" });
    const result = el("div");
    const form = el("form", { className: "sql-form" },
      query,
      el("div", { className: "toolbar" },
        el("button", { type: "submit" }, "Run"),
        el("label", { htmlFor: "sql-rollback" }, rollback, " Roll back afterwards (try a change safely)"),
        el("span", { className: "hint" }, "Ctrl+Enter runs")));
    const run = () => {
      sessionStorage.setItem("kilnbase-studio-sql", query.value);
      result.replaceChildren(el("p", { className: "hint" }, "Running…"));
      api<SqlResult>("/api/sql", { query: query.value, rollback: rollback.checked })
        .then((r) => {
          const rows = r.rows.map((values) => Object.fromEntries(r.columns.map((c, i) => [c, values[i] ?? null])));
          result.replaceChildren(
            el("p", { className: r.committed ? "ok" : "hint" },
              `${r.status}${r.committed ? "" : " (rolled back)"}${r.truncated ? `, first ${r.rows.length} rows shown` : ""}`),
            r.columns.length ? table(rows as Row[], r.columns) : "");
        })
        .catch((err: unknown) => fail(err, result));
    };
    form.addEventListener("submit", (e) => { e.preventDefault(); run(); });
    query.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); } });
    return [
      el("p", { className: "hint" },
        "Runs as the database superuser in one transaction (15 s limit). Schema changes made here are not recorded in db/migrations; ",
        "use `kilnbase migrate new` for changes you want to keep."),
      form, result,
    ];
  },

  async storage() {
    const buckets = await api<Bucket[]>("/api/buckets");
    const browser = el("div");

    function open(bucket: string, prefix: string): void {
      const q = (name: string) => `name=${encodeURIComponent(name)}`;
      const base = `/api/buckets/${encodeURIComponent(bucket)}`;
      browser.replaceChildren(el("p", { className: "hint" }, "Loading…"));
      api<StoredObject[]>(`${base}/objects?prefix=${encodeURIComponent(prefix)}`).then((items) => {
        // Breadcrumbs: bucket / folder / folder
        const parts = prefix.split("/").filter(Boolean);
        const crumbs = [el("button", { type: "button", className: "link" }, bucket)];
        crumbs[0]!.addEventListener("click", () => open(bucket, ""));
        parts.forEach((p, i) => {
          const b = el("button", { type: "button", className: "link" }, p);
          b.addEventListener("click", () => open(bucket, parts.slice(0, i + 1).join("/") + "/"));
          crumbs.push(el("span", {}, " / ") as unknown as HTMLButtonElement, b);
        });

        const file = el("input", { type: "file", id: "upload", multiple: true });
        const message = el("span", { className: "hint" });
        file.addEventListener("change", () => {
          const files = [...(file.files ?? [])];
          message.textContent = `Uploading ${files.length} file(s)…`;
          Promise.all(files.map((f) => request(`${base}/object?${q(prefix + f.name)}`, {
            method: "POST", body: f, headers: { "Content-Type": f.type || "application/octet-stream" },
          }))).then(() => open(bucket, prefix)).catch((err: unknown) => fail(err, message));
        });

        const rows = items.map((o) => {
          const name = el("td", {});
          const actions = el("td", { className: "actions" });
          if (o.folder) {
            const b = el("button", { type: "button", className: "link" }, `📁 ${o.name}`);
            b.addEventListener("click", () => open(bucket, prefix + o.name));
            name.append(b);
          } else {
            name.append(o.name);
            const dl = el("button", { type: "button" }, "Download");
            dl.addEventListener("click", () => {
              request(`${base}/object?${q(prefix + o.name)}`).then((r) => r.blob()).then((blob) => {
                const a = el("a", { href: URL.createObjectURL(blob), download: o.name });
                a.click();
                setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
              }).catch((err: unknown) => fail(err, message));
            });
            const del = el("button", { type: "button", className: "danger" }, "Delete");
            del.addEventListener("click", () => {
              if (!confirm(`Delete ${prefix + o.name}? This cannot be undone.`)) return;
              request(`${base}/object/delete?${q(prefix + o.name)}`, { method: "POST" })
                .then(() => open(bucket, prefix)).catch((err: unknown) => fail(err, message));
            });
            actions.append(dl, del);
          }
          return el("tr", {}, name, el("td", {}, o.mime_type ?? ""), el("td", {}, size(o.size)),
            el("td", { title: o.updated_at }, new Date(o.updated_at).toLocaleString()), actions);
        });
        browser.replaceChildren(
          el("div", { className: "toolbar" }, el("strong", {}, ...crumbs),
            el("label", { htmlFor: "upload", className: "button" }, "Upload files"), file, message),
          rows.length
            ? el("div", { className: "scroll" }, el("table", {},
                el("thead", {}, el("tr", {}, ...["name", "type", "size", "updated", ""].map((h) => el("th", {}, h)))),
                el("tbody", {}, ...rows)))
            : el("p", { className: "hint" }, "Empty. Upload files to add them here."),
          items.length === 500 ? el("p", { className: "hint" }, "Showing the first 500 entries.") : "");
      }).catch((err: unknown) => fail(err, browser));
    }

    const list = el("div", { className: "buckets" }, ...buckets.map((b) => {
      const button = el("button", { type: "button" },
        el("strong", {}, b.id), el("br"),
        el("small", {}, `${b.public ? "public" : "private"} · ${b.objects} file(s) · ${size(b.bytes)}`));
      button.addEventListener("click", () => {
        for (const other of list.querySelectorAll("button")) other.removeAttribute("aria-current");
        button.setAttribute("aria-current", "page");
        open(b.id, "");
      });
      return button;
    }));

    const id = el("input", { id: "bucket-id", required: true, pattern: "[a-z0-9][a-z0-9._\\-]{0,62}", placeholder: "avatars" });
    const isPublic = el("input", { type: "checkbox", id: "bucket-public" });
    const message = el("p", { className: "hint" });
    const create = el("form", {},
      el("label", { htmlFor: "bucket-id" }, "New bucket"), id,
      el("label", { htmlFor: "bucket-public" }, isPublic, " Public (anyone with the URL can read files)"),
      el("button", { type: "submit" }, "Create"), message);
    create.addEventListener("submit", (e) => {
      e.preventDefault();
      api("/api/buckets", { id: id.value, public: isPublic.checked })
        .then(() => show("storage")).catch((err: unknown) => fail(err, message));
    });
    return [
      el("p", { className: "hint" }, "Files are read and written as service_role; storage policies apply to API users, not here."),
      create,
      buckets.length ? list : el("p", { className: "hint" }, "No buckets yet."),
      browser,
    ];
  },

  async database() {
    const info = await api<DatabaseInfo>("/api/database");
    const message = el("p", { className: "hint" });
    const stat = (label: string, value: string) => el("div", { className: "stat" }, el("small", {}, label), el("strong", {}, value));
    const search = el("input", { type: "search", id: "ext-search", placeholder: "filter extensions…" });
    const body = el("tbody");
    const render = () => body.replaceChildren(...info.extensions
      .filter((x) => !search.value || `${x.name} ${x.comment ?? ""}`.toLowerCase().includes(search.value.toLowerCase()))
      .map((x) => {
        const on = x.installed_version !== null;
        const button = el("button", { type: "button", className: on ? "danger" : "" }, on ? "Disable" : "Enable");
        button.disabled = x.name === "plpgsql";
        button.addEventListener("click", () => {
          if (on && !confirm(`Drop extension ${x.name}? Objects that depend on it make this fail; nothing is dropped with it.`)) return;
          api(`/api/extensions/${encodeURIComponent(x.name)}/${on ? "disable" : "enable"}`, {})
            .then(() => show("database")).catch((err: unknown) => fail(err, message));
        });
        return el("tr", {},
          el("td", {}, el("strong", {}, x.name)),
          el("td", {}, on ? el("span", { className: "ok" }, `${x.installed_version} in ${x.schema}`) : el("span", { className: "hint" }, x.default_version)),
          el("td", {}, x.comment ?? ""),
          el("td", { className: "actions" }, button));
      }));
    search.addEventListener("input", render);
    render();
    return [
      el("div", { className: "stats" },
        stat("Postgres", info.version),
        stat("Size", size(info.bytes)),
        stat("Connections", `${info.connections} / ${info.max_connections}`),
        stat("Tables in public", String(info.tables)),
        stat("Up since", new Date(info.started_at).toLocaleString())),
      el("h2", {}, "Extensions"),
      el("p", { className: "hint" }, "Changes here are not recorded in db/migrations; add the same `create extension` to a migration to keep them."),
      el("form", {}, el("label", { htmlFor: "ext-search" }, "Filter"), search),
      message,
      el("div", { className: "scroll" }, el("table", {},
        el("thead", {}, el("tr", {}, ...["name", "version", "description", ""].map((h) => el("th", {}, h)))), body)),
    ];
  },

  async connect() {
    const info = await api<{ url: string; anon_key: string }>("/api/connect");
    const field = (label: string, value: string) => el("div", { className: "toolbar" },
      el("strong", {}, label), el("code", { className: "secretish" }, value), copyButton(value));
    const js = `import { createClient } from "kilnbase";\n\nconst kb = createClient("${info.url}", "${info.anon_key}");\nconst { data, error } = await kb.from("todos").select();`;
    const py = `from kilnbase import create_client\n\nkb = create_client("${info.url}", "${info.anon_key}")\nrows = kb.from_("todos").select().execute()`;
    const curl = `curl "${info.url}/rest/v1/todos?select=*" -H "apikey: ${info.anon_key}"`;
    return [
      el("p", { className: "hint" }, "The anon key is meant for browsers and apps; row level security decides what it can reach. Never ship the service_role key."),
      field("API URL", info.url),
      field("anon key", info.anon_key),
      ...[["JavaScript", js], ["Python", py], ["curl", curl]].flatMap(([title, code]) => [
        el("h2", {}, title!, " ", copyButton(code!)), el("pre", { className: "code" }, code!)]),
    ];
  },

  async viewas() {
    const [tables, users] = await Promise.all([api<TableInfo[]>("/api/tables"), api<User[]>("/api/users")]);
    const tableSelect = el("select", { id: "va-table", required: true },
      ...tables.map((t) => el("option", { value: t.name }, t.name)));
    const userSelect = el("select", { id: "va-user" }, el("option", { value: "" }, "anon (no user)"),
      ...users.map((u) => el("option", { value: u.id }, u.email ?? `${u.id} (anonymous)`)));
    const result = el("div");
    const form = el("form", {},
      el("label", { htmlFor: "va-table" }, "Table"), tableSelect,
      el("label", { htmlFor: "va-user" }, "as"), userSelect,
      el("button", { type: "submit" }, "Show rows"));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      result.replaceChildren(el("p", { className: "hint" }, "Loading…"));
      api<ViewAsResult>("/api/view-as", { table: tableSelect.value, user_id: userSelect.value || null })
        .then((r) => result.replaceChildren(
          el("p", {}, `Role ${r.role}. `, r.denied
            ? el("span", { className: "error" }, "Permission denied: the API answers this request with an error.")
            : `${r.rows.length} row(s), exactly what the REST API returns for this caller (first 50).`),
          table(r.rows),
          el("details", {}, el("summary", {}, "Claims used (auth.jwt())"), el("pre", {}, JSON.stringify(r.claims, null, 2)))))
        .catch((err: unknown) => fail(err, result));
    });
    return [el("p", { className: "hint" }, "Runs the query as that user, with the claims their access token carries, and rolls back."), form, result];
  },

  async users() {
    const result = el("div");
    const search = el("input", { type: "search", placeholder: "email contains…", id: "user-search" });
    const act = (u: User, action: string, question: string) => {
      if (!confirm(question)) return;
      api(`/api/users/${u.id}/${action}`, {}).then(() => load()).catch((err: unknown) => fail(err, result));
    };
    const row = (u: User) => {
      const buttons: HTMLButtonElement[] = [];
      const button = (label: string, action: string, question: string, danger = false) => {
        const b = el("button", { type: "button", className: danger ? "danger" : "" }, label);
        b.addEventListener("click", () => act(u, action, question));
        buttons.push(b);
      };
      if (u.email && !u.email_confirmed_at) button("Confirm email", "confirm-email", `Mark ${u.email} as confirmed?`);
      if (u.active_sessions > 0) {
        button("Sign out", "sign-out", "End all sessions? Refresh tokens stop working now; access tokens already issued stay valid for up to an hour.");
      }
      button("Delete", "delete", `Delete ${u.email ?? u.id} and everything linked to the account? This cannot be undone.`, true);
      return el("tr", {},
        el("td", {}, u.email ?? el("span", { className: "hint" }, "anonymous")),
        el("td", {}, u.email_confirmed_at ? el("span", { className: "ok" }, "confirmed") : el("span", { className: "hint" }, "unconfirmed")),
        el("td", { title: u.last_sign_in_at ?? "" }, u.last_sign_in_at ? new Date(u.last_sign_in_at).toLocaleString() : "never"),
        el("td", {}, String(u.active_sessions)),
        el("td", { title: u.created_at }, new Date(u.created_at).toLocaleString()),
        el("td", {}, el("code", {}, u.id)),
        el("td", { className: "actions" }, ...buttons));
    };
    const load = () => api<User[]>(`/api/users?search=${encodeURIComponent(search.value)}`)
      .then((users) => result.replaceChildren(users.length
        ? el("div", { className: "scroll" }, el("table", {},
            el("thead", {}, el("tr", {}, ...["email", "status", "last sign-in", "sessions", "created", "id", ""].map((h) => el("th", {}, h)))),
            el("tbody", {}, ...users.map(row))))
        : el("p", { className: "hint" }, "No users.")))
      .catch((err: unknown) => fail(err, result));
    const form = el("form", {}, el("label", { htmlFor: "user-search" }, "Search"), search, el("button", { type: "submit" }, "Find"));
    form.addEventListener("submit", (e) => { e.preventDefault(); void load(); });

    const email = el("input", { type: "email", id: "new-email", required: true, placeholder: "user@example.com" });
    const password = el("input", { type: "password", id: "new-password", autocomplete: "new-password", placeholder: "empty: link / code / provider only" });
    const confirmed = el("input", { type: "checkbox", id: "new-confirmed", checked: true });
    const message = el("p", { className: "hint" });
    const create = el("form", {},
      el("label", { htmlFor: "new-email" }, "New user"), email,
      el("label", { htmlFor: "new-password" }, "Password"), password,
      el("label", { htmlFor: "new-confirmed" }, confirmed, " Email confirmed"),
      el("button", { type: "submit" }, "Create"), message);
    create.addEventListener("submit", (e) => {
      e.preventDefault();
      api<User>("/api/users", { email: email.value, password: password.value || null, email_confirmed: confirmed.checked })
        .then(() => { email.value = ""; password.value = ""; message.textContent = "Created."; void load(); })
        .catch((err: unknown) => fail(err, message));
    });
    void load();
    return [form, create, result];
  },

  async webhooks() {
    const [hooks, deliveries, tables] = await Promise.all([
      api<Webhook[]>("/api/webhooks"), api<Delivery[]>("/api/webhook-deliveries"), api<TableInfo[]>("/api/tables"),
    ]);
    const message = el("p", { className: "hint" });
    const act = (path: string, question?: string) => {
      if (question && !confirm(question)) return;
      api(path, {}).then(() => show("webhooks")).catch((err: unknown) => fail(err, message));
    };

    const hookRows = hooks.map((w) => {
      const toggle = el("button", { type: "button" }, w.enabled ? "Disable" : "Enable");
      toggle.addEventListener("click", () => act(`/api/webhooks/${encodeURIComponent(w.name)}/${w.enabled ? "disable" : "enable"}`));
      const del = el("button", { type: "button", className: "danger" }, "Delete");
      del.addEventListener("click", () => act(`/api/webhooks/${encodeURIComponent(w.name)}/delete`,
        `Delete webhook ${w.name} and its delivery log?`));
      return el("tr", {},
        el("td", {}, w.name), el("td", {}, el("code", {}, w.table)), el("td", {}, w.events.join(", ")),
        el("td", {}, el("code", {}, w.host)),
        el("td", {}, w.enabled ? el("span", { className: "ok" }, "on") : el("span", { className: "hint" }, "off")),
        el("td", {}, `${w.pending} pending`, w.failed ? el("span", { className: "error" }, ` · ${w.failed} failed`) : ""),
        el("td", { className: "actions" }, toggle, del));
    });

    const deliveryRows = deliveries.map((d) => {
      const actions = el("td", { className: "actions" });
      if (d.status === "failed") {
        const retry = el("button", { type: "button" }, "Retry");
        retry.addEventListener("click", () => act(`/api/webhook-deliveries/${d.id}/retry`));
        actions.append(retry);
      }
      return el("tr", {},
        el("td", {}, String(d.id)), el("td", {}, d.webhook),
        el("td", {}, el("span", { className: d.status === "failed" ? "error" : d.status === "delivered" ? "ok" : "hint" }, d.status)),
        el("td", {}, String(d.attempts)), el("td", {}, d.last_status === null ? "" : String(d.last_status)),
        el("td", {}, el("code", {}, d.last_error ?? "")),
        el("td", { title: d.created_at }, new Date(d.created_at).toLocaleString()), actions);
    });

    const name = el("input", { id: "hook-name", required: true, placeholder: "new-orders" });
    const target = el("select", { id: "hook-table" }, ...tables.map((t) => el("option", { value: `public.${t.name}` }, t.name)));
    const url = el("input", { id: "hook-url", type: "url", required: true, placeholder: "https://example.com/hooks/orders" });
    const events = ["INSERT", "UPDATE", "DELETE"].map((e) => el("input", { type: "checkbox", value: e, id: `hook-${e}`, checked: e === "INSERT" }));
    const secret = el("div");
    const create = el("form", {},
      el("label", { htmlFor: "hook-name" }, "New webhook"), name,
      el("label", { htmlFor: "hook-table" }, "on"), target,
      ...events.map((e) => el("label", { htmlFor: e.id }, e, ` ${e.value}`)),
      el("label", { htmlFor: "hook-url" }, "POST to"), url,
      el("button", { type: "submit" }, "Create"));
    create.addEventListener("submit", (e) => {
      e.preventDefault();
      const chosen = events.filter((c) => c.checked).map((c) => c.value);
      api<{ name: string; secret: string }>("/api/webhooks", { name: name.value, table: target.value, events: chosen, url: url.value })
        .then((r) => {
          void show("webhooks").then(() => view.prepend(el("div", { className: "notice" },
            el("p", {}, `Webhook ${r.name} created. Its signing secret (X-Kilnbase-Signature) is shown only now:`),
            el("pre", {}, r.secret))));
        })
        .catch((err: unknown) => fail(err, secret));
    });

    const grid = (head: string[], rows: HTMLElement[], empty: string) => rows.length
      ? el("div", { className: "scroll" }, el("table", {}, el("thead", {}, el("tr", {}, ...head.map((h) => el("th", {}, h)))), el("tbody", {}, ...rows)))
      : el("p", { className: "hint" }, empty);
    return [
      create, secret, message,
      el("h2", {}, "Webhooks"),
      grid(["name", "table", "events", "target", "", "queue", ""], hookRows, "No webhooks yet."),
      el("h2", {}, "Newest deliveries"),
      grid(["id", "webhook", "status", "attempts", "HTTP", "last error", "queued", ""], deliveryRows, "No deliveries yet."),
    ];
  },
};

function fail(err: unknown, target: HTMLElement): void {
  if (err instanceof SignedOut) return signOut("The key was rejected.");
  target.replaceChildren(el("p", { className: "error", role: "alert" }, err instanceof Error ? err.message : String(err)));
}

async function show(name: string): Promise<void> {
  for (const b of document.querySelectorAll<HTMLButtonElement>("#nav [data-view]")) {
    if (b.dataset.view === name) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  view.replaceChildren(el("p", { className: "hint" }, "Loading…"));
  try {
    view.replaceChildren(...(await views[name]!()));
  } catch (err) {
    fail(err, view);
  }
}

function signIn(): void {
  $("login").hidden = true;
  $("nav").hidden = false;
  void show("tables");
}

function signOut(message = ""): void {
  sessionStorage.removeItem(KEY);
  view.replaceChildren();
  $("nav").hidden = true;
  $("login").hidden = false;
  $("login-error").textContent = message;
}

$<HTMLFormElement>("login").addEventListener("submit", (e) => {
  e.preventDefault();
  sessionStorage.setItem(KEY, $<HTMLInputElement>("key").value.trim());
  $<HTMLInputElement>("key").value = "";
  signIn();
});
for (const b of document.querySelectorAll<HTMLButtonElement>("#nav [data-view]")) {
  b.addEventListener("click", () => void show(b.dataset.view ?? "tables"));
}
$("signout").addEventListener("click", () => signOut());
if (sessionStorage.getItem(KEY)) signIn();

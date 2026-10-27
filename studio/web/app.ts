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

const views: Record<string, () => Promise<Node[]>> = {
  async tables() {
    const tables = await api<TableInfo[]>("/api/tables");
    return tables.flatMap((t) => [
      el("h2", {}, `public.${t.name} `,
        el("span", { className: t.rls ? "ok" : "error" }, t.rls ? "RLS on" : "RLS off: hidden from the API")),
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
    const rows = await api<Row[]>("/api/webhook-deliveries");
    return [el("p", { className: "hint" }, "Newest 50 deliveries. Configure webhooks with kilnbase.create_webhook()."), table(rows)];
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

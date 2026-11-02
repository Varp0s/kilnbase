import "./style.css";
import { confirmDialog, emptyState, loadFont, skeleton, themeButton, toast } from "./ui";
import {
  api, badge, button, copyButton, details, downloadText, el, fail, field, grid, hint, icon,
  message, nav, option, PAGE, panel, parseCsv, pre, quoteIdent, report, request, runSql,
  size, table, text, toCsv, when,
} from "./lib";
import type { Column, Connect, Json, Policy, Row, RowsPage, SqlResult, TableInfo, User } from "./lib";
import { databaseViews } from "./database";
import { authViews } from "./auth";
import { platformViews } from "./platform";

// Studio UI. Rows written by end users are shown on a page that holds the service_role key, so
// everything is rendered with textContent / DOM APIs; innerHTML is never used.

const KEY = "kilnbase-studio-key";
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const view = $<HTMLElement>("view");

interface Bucket { id: string; public: boolean; file_size_limit: number | null; allowed_mime_types: string[] | null; objects: number; bytes: number; created_at: string }
interface StoredObject { name: string; size: number | null; mime_type: string | null; updated_at: string; folder: boolean }
interface Webhook {
  name: string; table: string; events: string[]; enabled: boolean; host: string;
  pending: number; failed: number; created_at: string;
}
interface Delivery { id: number; webhook: string; status: string; attempts: number; last_status: number | null; last_error: string | null; created_at: string }
interface CronJob {
  jobid: number; name: string | null; schedule: string; command: string; active: boolean; username: string;
  last_status: string | null; last_run: string | null;
}
interface CronRun { runid: number; job: string; status: string; return_message: string | null; start_time: string | null; end_time: string | null }
interface CronInfo { enabled: boolean; jobs: CronJob[]; runs: CronRun[] }
interface Queue { name: string; created_at: string; is_unlogged: boolean; queue_length: number; total_messages: number; oldest_msg_age_sec: number | null }
interface QueueMessage { msg_id: number; read_ct: number; enqueued_at: string; vt: string; message: string }
interface Extension { name: string; default_version: string; installed_version: string | null; comment: string | null; schema: string | null }
interface DatabaseInfo {
  version: string; bytes: number; connections: number; max_connections: number; tables: number;
  started_at: string; extensions: Extension[];
}
interface Overview {
  tables: number; tables_without_rls: number; users: number; new_users: number; sessions: number;
  buckets: number; files: number; file_bytes: number; webhooks: number; failed_deliveries: number;
  database_bytes: number; version: string; errors_24h: number; recent_errors: Row[];
}
interface StoragePolicy { name: string; table: string; command: string; roles: string[]; using: string | null; check: string | null }

const COLUMN_TYPES = ["text", "integer", "bigint", "boolean", "numeric", "double precision", "uuid", "timestamptz", "date", "jsonb", "text[]", "bytea"];
const OPS: [string, string][] = [["eq", "="], ["neq", "≠"], ["gt", ">"], ["gte", "≥"], ["lt", "<"], ["lte", "≤"], ["like", "contains"], ["is", "is"]];

/** Inputs hold text; JSON and array columns are parsed, everything else is cast by Postgres. */
function parseInput(column: Column, raw: string): Json {
  return /(\[\]|json|jsonb)$/.test(column.type) ? (JSON.parse(raw) as Json) : raw;
}

/** The column part of a CREATE TABLE / ADD COLUMN statement, from the editor's fields. */
function columnSql(c: { name: string; type: string; nullable: boolean; default: string; primary: boolean }): string {
  return `${quoteIdent(c.name)} ${c.type}${c.primary ? " primary key" : ""}${c.nullable || c.primary ? "" : " not null"}${c.default ? ` default ${c.default}` : ""}`;
}

/** One row of the column builder (new table / add column). */
function columnFields(initial: Partial<{ name: string; type: string; primary: boolean }> = {}) {
  const name = el("input", { placeholder: "column", required: true, value: initial.name ?? "" });
  const type = el("select", {}, ...COLUMN_TYPES.map((t) => option(t)));
  type.value = initial.type ?? "text";
  const nullable = el("input", { type: "checkbox", checked: !initial.primary });
  const def = el("input", { placeholder: "default (SQL)" });
  const primary = el("input", { type: "checkbox", checked: !!initial.primary });
  const row = el("div", { className: "column-row" }, name, type,
    el("label", {}, nullable, " nullable"), def, el("label", {}, primary, " primary key"));
  return { row, value: () => ({ name: name.value.trim(), type: type.value, nullable: nullable.checked, default: def.value.trim(), primary: primary.checked }) };
}

function newTableForm(): HTMLElement {
  const name = el("input", { id: "new-table", required: true, placeholder: "orders", pattern: "[a-z_][a-z0-9_]*" });
  const rls = el("input", { type: "checkbox", id: "new-rls", checked: true });
  const columns = [columnFields({ name: "id", type: "bigint", primary: true }), columnFields({ name: "created_at", type: "timestamptz" })];
  const list = el("div", {}, ...columns.map((c) => c.row));
  const add = button("Add column", () => { const c = columnFields(); columns.push(c); list.append(c.row); });
  const form = el("form", { className: "builder" },
    field("Table name", name), list, add,
    el("label", { htmlFor: "new-rls" }, rls, " Enable row level security (the table stays hidden from the API until it has policies)"),
    el("button", { type: "submit" }, "Review SQL"));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const cols = columns.map((c) => c.value()).filter((c) => c.name);
    if (cols.length === 0) return;
    const t = `public.${quoteIdent(name.value.trim())}`;
    const defaults = cols.map((c) => c.name === "created_at" && !c.default ? { ...c, default: "now()" } : c.name === "id" && c.type === "bigint" && c.primary ? { ...c, type: "bigint generated always as identity" } : c);
    const sql = `create table ${t} (\n  ${defaults.map(columnSql).join(",\n  ")}\n);\n${rls.checked ? `alter table ${t} enable row level security;\n` : ""}`;
    void runSql(sql, { title: `Create ${name.value}?`, confirmLabel: "Create table", success: `Created ${name.value}` })
      .then((ok) => { if (ok) void nav.show(`data/${name.value.trim()}`); });
  });
  return form;
}

/** One table's rows, a page at a time, with filter, sort, add / edit / delete, import and export. */
function dataEditor(name: string): HTMLElement {
  const box = el("div");
  let offset = 0, sort = "", desc = false;
  let filter = { column: "", op: "eq", value: "" };
  const table = `public.${quoteIdent(name)}`;

  const write = (action: string, body: unknown) =>
    api<{ row: Row; inserted?: number }>(`/api/tables/${encodeURIComponent(name)}/rows?action=${action}`, body);

  function rowForm(page: RowsPage, row: Row | null): HTMLFormElement {
    const inputs = new Map<string, HTMLInputElement>();
    const fields = page.columns.map((c) => {
      const input = el("input", {
        value: row ? text(row[c.name]) : "",
        placeholder: row ? "" : (c.default ?? (c.nullable ? "null" : "required")),
        disabled: c.read_only,
      });
      inputs.set(c.name, input);
      return field(c.name, input, c.type);
    });
    const msg = el("p", { className: "hint" });
    const cancel = button("Cancel", () => render());
    const form = el("form", { className: "row-form" }, ...fields,
      el("button", { type: "submit" }, row ? "Save" : "Insert"), cancel, msg);
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
        msg.textContent = `Not valid JSON: ${message(err)}`;
        return;
      }
      if (row !== null && Object.keys(values).length === 0) return void render();
      const key = row === null ? undefined : Object.fromEntries(page.key.map((k) => [k, row[k] ?? null]));
      write(row === null ? "insert" : "update", { key, values })
        .then(() => { toast(row === null ? "Row added" : "Row saved"); void render(); })
        .catch((err: unknown) => fail(err, msg));
    });
    return form;
  }

  function addColumnForm(): HTMLElement {
    const c = columnFields();
    const msg = el("p", { className: "hint" });
    const form = el("form", { className: "builder" }, el("h3", {}, "Add column"), c.row,
      el("button", { type: "submit" }, "Review SQL"), button("Cancel", () => render()), msg);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const v = c.value();
      if (!v.name) return;
      void runSql(`alter table ${table} add column ${columnSql(v)};\n`, { title: `Add ${v.name} to ${name}?`, confirmLabel: "Add column", success: "Column added" })
        .then((ok) => { if (ok) void render(); });
    });
    return form;
  }

  function columnsPanel(page: RowsPage): HTMLElement {
    const rows = page.columns.map((c) => el("tr", {},
      el("td", {}, el("strong", {}, c.name), ...(c.primary_key ? [" ", badge("primary key", "ok")] : [])),
      el("td", {}, el("code", {}, c.type)), el("td", {}, c.nullable ? "nullable" : "not null"),
      el("td", {}, el("code", {}, c.default ?? "")),
      el("td", { className: "actions" }, button("Drop", () => runSql(`alter table ${table} drop column ${quoteIdent(c.name)};\n`,
        { title: `Drop column ${c.name}?`, confirmLabel: "Drop column", danger: true, success: "Column dropped" }).then((ok) => { if (ok) void render(); }), "danger"))));
    return el("div", {}, el("h3", {}, `Columns of ${name}`), grid(["name", "type", "null", "default", ""], rows, "No columns"), button("Back to rows", () => render()));
  }

  async function importCsv(file: File, page: RowsPage): Promise<void> {
    const parsed = parseCsv(await file.text());
    const [head, ...lines] = parsed;
    if (!head || lines.length === 0) throw new Error("The file has no data rows.");
    const unknown = head.filter((h) => !page.columns.some((c) => c.name === h));
    if (unknown.length) throw new Error(`No such column(s): ${unknown.join(", ")}`);
    const cols = head.map((h) => page.columns.find((c) => c.name === h)!);
    const rows = lines.map((line) => Object.fromEntries(cols.map((c, i) => {
      const raw = line[i] ?? "";
      if (raw === "") return [c.name, null];
      try { return [c.name, parseInput(c, raw)]; } catch { return [c.name, raw]; }
    })));
    let inserted = 0;
    for (let i = 0; i < rows.length; i += 500) {
      const r = await write("insert-many", { values: rows.slice(i, i + 500) });
      inserted += r.inserted ?? 0;
    }
    toast(`Imported ${inserted} row(s)`);
  }

  async function render(): Promise<void> {
    box.replaceChildren(skeleton());
    try {
      const params = new URLSearchParams({ offset: String(offset), limit: String(PAGE), sort, desc: String(desc) });
      if (filter.column) { params.set("column", filter.column); params.set("op", filter.op); params.set("value", filter.value); }
      const page = await api<RowsPage>(`/api/tables/${encodeURIComponent(name)}/rows?${params}`);
      const editable = page.key.length > 0;
      const cols = page.columns.map((c) => c.name);
      const head = el("tr", {}, ...cols.map((c) => {
        const b = el("button", { type: "button", className: "sort" }, c, sort === c ? (desc ? " ↓" : " ↑") : "");
        b.addEventListener("click", () => { if (sort !== c) { sort = c; desc = false; } else if (!desc) desc = true; else sort = ""; offset = 0; void render(); });
        return el("th", {}, b);
      }), editable ? el("th", {}) : "");
      const body = page.rows.map((r) => {
        const cells = cols.map((c) => el("td", {}, el("code", {}, text(r[c]))));
        if (!editable) return el("tr", {}, ...cells);
        const editBtn = button("Edit", () => box.replaceChildren(el("h3", {}, "Edit row"), rowForm(page, r)));
        const delBtn = button("Delete", async () => {
          if (!(await confirmDialog("Delete this row?", "This cannot be undone.", { confirmLabel: "Delete row", danger: true }))) return;
          const key = Object.fromEntries(page.key.map((k) => [k, r[k] ?? null]));
          write("delete", { key }).then(() => { toast("Row deleted"); void render(); }).catch((err: unknown) => fail(err, box));
        }, "danger");
        return el("tr", {}, ...cells, el("td", { className: "actions" }, editBtn, delBtn));
      });

      // Filter bar
      const column = el("select", {}, option("", "filter…"), ...cols.map((c) => option(c)));
      column.value = filter.column;
      const op = el("select", {}, ...OPS.map(([v, l]) => option(v, l)));
      op.value = filter.op;
      const value = el("input", { placeholder: "value", value: filter.value });
      const sync = () => { value.hidden = op.value === "is"; if (op.value === "is") value.value = ""; };
      op.addEventListener("change", sync); sync();
      const isNull = el("select", {}, option("null"), option("not null"));
      isNull.hidden = op.value !== "is";
      op.addEventListener("change", () => { isNull.hidden = op.value !== "is"; });
      if (op.value === "is") isNull.value = filter.value || "null";
      const filterForm = el("form", { className: "toolbar filter" }, column, op, value, isNull,
        el("button", { type: "submit", className: "small" }, "Apply"),
        filter.column ? button("Clear", () => { filter = { column: "", op: "eq", value: "" }; offset = 0; void render(); }, "small") : "");
      filterForm.addEventListener("submit", (e) => {
        e.preventDefault();
        filter = { column: column.value, op: op.value, value: op.value === "is" ? isNull.value : value.value };
        offset = 0; void render();
      });

      const prev = button("← Previous", () => { offset = Math.max(0, offset - PAGE); void render(); });
      prev.disabled = offset === 0;
      const next = button("Next →", () => { offset += PAGE; void render(); });
      next.disabled = offset + page.rows.length >= page.total;
      const add = button([icon("table"), "Add row"], () => box.replaceChildren(el("h3", {}, "New row"), rowForm(page, null)));
      add.disabled = !editable;
      const file = el("input", { type: "file", id: "csv-import", accept: ".csv,text/csv" });
      file.addEventListener("change", () => {
        const f = file.files?.[0];
        if (!f) return;
        box.replaceChildren(skeleton(3));
        importCsv(f, page).then(() => render()).catch((err: unknown) => { report(err); void render(); });
      });
      const exportBtn = button([icon("download"), "Export CSV"], () =>
        request(`/api/tables/${encodeURIComponent(name)}/export`).then((r) => r.text())
          .then((csv) => downloadText(`${name}.csv`, csv, "text/csv")).catch(report));
      const dropBtn = button("Drop table", () => runSql(`drop table ${table};\n`, { title: `Drop ${name}?`, confirmLabel: "Drop table", danger: true, success: `Dropped ${name}` })
        .then((ok) => { if (ok) void nav.show("data"); }), "danger");
      box.replaceChildren(
        el("div", { className: "toolbar" }, add, el("label", { htmlFor: "csv-import", className: "button" }, icon("upload"), "Import CSV"), file, exportBtn,
          button("Columns", () => box.replaceChildren(columnsPanel(page))), button("Add column", () => box.replaceChildren(addColumnForm())),
          dropBtn,
          el("span", { className: "spacer" }), prev, next,
          el("span", { className: "hint" }, page.total ? `Rows ${offset + 1}–${offset + page.rows.length} of ${page.total.toLocaleString()}` : "0 rows")),
        filterForm,
        editable ? "" : hint("No primary key: rows are read-only here. Add one in the SQL editor to edit them."),
        page.rows.length
          ? el("div", { className: "scroll" }, el("table", {}, el("thead", {}, head), el("tbody", {}, ...body)))
          : emptyState(icon("table"), filter.column ? "No rows match" : "No rows yet", editable && !filter.column ? "Add the first one with Add row, or import a CSV." : ""));
    } catch (err) {
      fail(err, box);
    }
  }

  void render();
  return box;
}

const POLICY_TEMPLATES: [string, Partial<{ command: string; roles: string; using: string; check: string }>][] = [
  ["Own rows (read & write)", { command: "ALL", roles: "authenticated", using: "owner = auth.uid()", check: "owner = auth.uid()" }],
  ["Public read", { command: "SELECT", roles: "anon, authenticated", using: "true", check: "" }],
  ["Signed-in users insert", { command: "INSERT", roles: "authenticated", using: "", check: "auth.uid() is not null" }],
  ["Verified email only", { command: "SELECT", roles: "authenticated", using: "coalesce((auth.jwt() ->> 'email_verified')::boolean, false)", check: "" }],
];

/** A form that writes `create policy` for one table; the SQL is shown before it runs. */
function policyForm(relation: string, onDone: () => void): HTMLElement {
  const name = el("input", { required: true, placeholder: "own rows" });
  const command = el("select", {}, ...["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"].map((c) => option(c)));
  const roles = el("input", { value: "authenticated", placeholder: "authenticated, anon" });
  const using = el("textarea", { rows: 2, spellcheck: false, placeholder: "owner = auth.uid()" });
  const check = el("textarea", { rows: 2, spellcheck: false, placeholder: "owner = auth.uid()" });
  const templates = el("div", { className: "chips" }, ...POLICY_TEMPLATES.map(([label, t]) => button(label, () => {
    name.value = name.value || label.toLowerCase();
    command.value = t.command ?? "ALL"; roles.value = t.roles ?? ""; using.value = t.using ?? ""; check.value = t.check ?? "";
  }, "small")));
  const form = el("form", { className: "builder" },
    el("h3", {}, `New policy on ${relation}`), templates,
    field("Name", name), field("Command", command), field("Roles", roles, "comma separated"),
    field("USING", using, "which rows are visible / may be changed"), field("WITH CHECK", check, "what new or changed rows must satisfy"),
    el("button", { type: "submit" }, "Review SQL"), button("Cancel", onDone));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const to = roles.value.split(",").map((r) => r.trim()).filter(Boolean).map(quoteIdent).join(", ");
    const parts = [`create policy ${quoteIdent(name.value)} on ${relation}`, `  for ${command.value.toLowerCase()}${to ? ` to ${to}` : ""}`];
    if (using.value.trim() && command.value !== "INSERT") parts.push(`  using (${using.value.trim()})`);
    if (check.value.trim() && !["SELECT", "DELETE"].includes(command.value)) parts.push(`  with check (${check.value.trim()})`);
    void runSql(parts.join("\n") + ";\n", { title: `Create policy ${name.value}?`, confirmLabel: "Create policy", success: "Policy created" }).then((ok) => { if (ok) onDone(); });
  });
  return form;
}

function policyRows(relation: string, policies: Policy[], reload: () => void): HTMLElement[] {
  return policies.map((p) => el("tr", {},
    el("td", {}, el("strong", {}, p.name)), el("td", {}, p.command), el("td", {}, p.roles.join(", ")),
    el("td", {}, el("code", {}, p.using ?? "")), el("td", {}, el("code", {}, p.check ?? "")),
    el("td", { className: "actions" }, button("Drop", () => runSql(`drop policy ${quoteIdent(p.name)} on ${relation};\n`,
      { title: `Drop policy ${p.name}?`, confirmLabel: "Drop policy", danger: true, success: "Policy dropped" }).then((ok) => { if (ok) reload(); }), "danger"))));
}

const SQL_TEMPLATES: [string, string][] = [
  ["List tables", "select table_name, table_type from information_schema.tables\n where table_schema = 'public' order by 1;"],
  ["Create table", "create table public.todos (\n  id bigint generated always as identity primary key,\n  owner uuid not null default auth.uid(),\n  title text not null,\n  done boolean not null default false,\n  created_at timestamptz not null default now()\n);\nalter table public.todos enable row level security;\ncreate policy \"own rows\" on public.todos for all to authenticated\n  using (owner = auth.uid()) with check (owner = auth.uid());"],
  ["Enable realtime", "select kilnbase.enable_realtime('public.todos');"],
  ["Create index", "create index concurrently if not exists todos_owner_idx on public.todos (owner);"],
  ["Create function", "create or replace function public.hello(name text)\n returns text language sql stable as $$\n  select 'hello ' || name\n$$;"],
  ["Create enum", "create type public.status as enum ('draft', 'published', 'archived');"],
  ["Slow queries", "select calls, round(total_exec_time) as total_ms, round(mean_exec_time) as mean_ms, left(query, 120) as query\n  from pg_stat_statements order by total_exec_time desc limit 20;"],
  ["Table sizes", "select relname, pg_size_pretty(pg_total_relation_size(relid)) as size, n_live_tup as rows\n  from pg_stat_user_tables where schemaname = 'public' order by pg_total_relation_size(relid) desc;"],
];

function stored<T>(key: string, fallback: T): T {
  try { return (JSON.parse(localStorage.getItem(key) ?? "") as T) ?? fallback; } catch { return fallback; }
}
function store(key: string, value: unknown): void {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* private window: not remembered */ }
}

const views: Record<string, (sub: string) => Promise<Node[]>> = {
  async overview() {
    const o = await api<Overview>("/api/overview");
    const card = (view: string, ico: string, label: string, value: string, detail: string) => {
      const b = el("button", { type: "button", className: "card" },
        el("span", { className: "card-icon" }, icon(ico)),
        el("small", {}, label), el("strong", {}, value), el("span", { className: "hint" }, detail));
      b.addEventListener("click", () => void show(view));
      return b;
    };
    const checks: HTMLElement[] = [];
    const check = (good: boolean, okText: string, badText: string, view: string) => {
      const b = el("button", { type: "button", className: `check ${good ? "good" : "bad"}` },
        icon(good ? "check" : "alert"), good ? okText : badText);
      b.addEventListener("click", () => void show(view));
      checks.push(b);
    };
    check(o.tables_without_rls === 0, "Every table in public has row level security",
      `${o.tables_without_rls} table(s) without row level security are hidden from the API`, "tables");
    check(o.failed_deliveries === 0, "No failed webhook deliveries", `${o.failed_deliveries} webhook delivery(s) failed`, "webhooks");
    check(o.errors_24h === 0, "No errors logged in the last 24 hours", `${o.errors_24h} error(s) logged in the last 24 hours`, "logs");
    const errors = o.recent_errors.map((e) => el("tr", {},
      el("td", { className: "nowrap" }, when(e.ts)),
      el("td", {}, badge(text(e.service))),
      el("td", { className: "log-msg" }, text(e.msg))));
    return [
      el("div", { className: "cards" },
        card("tables", "table", "Tables", String(o.tables), o.tables_without_rls ? `${o.tables_without_rls} without RLS` : "all protected by RLS"),
        card("users", "users", "Users", String(o.users), `${o.new_users} new this week · ${o.sessions} active sessions`),
        card("storage", "folder", "Storage", size(o.file_bytes), `${o.files} file(s) in ${o.buckets} bucket(s)`),
        card("database", "database", "Database", size(o.database_bytes), `Postgres ${o.version.split(" ")[0]}`),
        card("webhooks", "bolt", "Webhooks", String(o.webhooks), o.failed_deliveries ? `${o.failed_deliveries} failed deliveries` : "no failures")),
      el("h2", {}, "Health ", button("Advisors →", () => show("advisors"), "small")),
      el("div", { className: "checks" }, ...checks),
      ...(errors.length ? [el("h2", {}, "Recent errors"), el("div", { className: "scroll" }, el("table", {}, el("tbody", {}, ...errors)))] : []),
    ];
  },

  async tables() {
    const tables = await api<TableInfo[]>("/api/tables");
    const holder = el("div");
    const reload = () => void show("tables");
    if (tables.length === 0) return [emptyState(icon("shield"), "No tables in public yet", "Create one in the table editor or the SQL editor."), button("Table editor", () => show("data"))];
    return [
      hint("Row level security decides which rows each caller sees through the API. A table with RLS off is hidden from the API; one with RLS on and no policies is readable by nobody."),
      holder,
      ...tables.flatMap((t) => {
        const relation = `public.${quoteIdent(t.name)}`;
        const toggle = button(t.rls ? "Disable RLS" : "Enable RLS", () => runSql(`alter table ${relation} ${t.rls ? "disable" : "enable"} row level security;\n`,
          { title: `${t.rls ? "Disable" : "Enable"} RLS on ${t.name}?`, confirmLabel: t.rls ? "Disable" : "Enable", danger: t.rls, success: "Done" }).then((ok) => { if (ok) reload(); }), "small");
        const add = button("New policy", () => { holder.replaceChildren(policyForm(relation, reload)); holder.scrollIntoView({ behavior: "smooth" }); }, "small");
        return [
          el("h2", {}, `public.${t.name} `, badge(t.rls ? "RLS on" : "RLS off: hidden from the API", t.rls ? "ok" : "error"), " ", toggle, add),
          t.policies.length
            ? grid(["name", "command", "roles", "using", "check", ""], policyRows(relation, t.policies, reload), "")
            : hint(t.rls ? "No policies: nobody can read it through the API." : ""),
        ];
      }),
    ];
  },

  async data(sub) {
    const tables = await api<TableInfo[]>("/api/tables");
    const holder = el("div");
    const create = button([icon("table"), "New table"], () => holder.replaceChildren(newTableForm()));
    if (tables.length === 0) return [emptyState(icon("table"), "No tables in public yet", "Create the first one here."), create, holder];
    const current = tables.some((t) => t.name === sub) ? sub : tables[0]!.name;
    const select = el("select", { id: "data-table" }, ...tables.map((t) => option(t.name)));
    select.value = current;
    holder.append(dataEditor(current));
    select.addEventListener("change", () => { history.replaceState(null, "", `#data/${select.value}`); holder.replaceChildren(dataEditor(select.value)); });
    return [
      hint("Edits run as service_role, so row level security does not apply. Values are cast by Postgres; JSON and array columns take JSON. Click a column header to sort."),
      el("form", {}, el("label", { htmlFor: "data-table" }, "Table"), select, create,
        button("API docs", () => show(`apidocs/${select.value}`), "small"), button("Policies", () => show("tables"), "small")),
      holder,
    ];
  },

  async sql() {
    const query = el("textarea", { id: "sql-query", rows: 10, spellcheck: false, placeholder: "select * from public.todos limit 10;" });
    query.value = sessionStorage.getItem("kilnbase-studio-sql") ?? "";
    const rollback = el("input", { type: "checkbox", id: "sql-rollback" });
    const result = el("div");
    let last: SqlResult | null = null;
    const exportBtn = button([icon("download"), "Export CSV"], () => { if (last) downloadText("result.csv", toCsv(last.columns, last.rows), "text/csv"); });
    exportBtn.disabled = true;
    const form = el("form", { className: "sql-form" },
      query,
      el("div", { className: "toolbar" },
        el("button", { type: "submit" }, "Run"),
        button("Explain", () => run(`explain (analyze, buffers) ${query.value}`, true)),
        el("label", { htmlFor: "sql-rollback" }, rollback, " Roll back afterwards (try a change safely)"),
        exportBtn,
        el("span", { className: "hint" }, "Ctrl+Enter runs")));
    const run = (sql = query.value, forceRollback = false) => {
      sessionStorage.setItem("kilnbase-studio-sql", query.value);
      const history = [query.value, ...stored<string[]>("kilnbase-studio-history", []).filter((q) => q !== query.value)].slice(0, 20);
      store("kilnbase-studio-history", history);
      renderSide();
      result.replaceChildren(el("p", { className: "hint" }, "Running…"));
      api<SqlResult>("/api/sql", { query: sql, rollback: rollback.checked || forceRollback })
        .then((r) => {
          last = r; exportBtn.disabled = r.columns.length === 0;
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

    // Side list: saved snippets (this browser), templates, history.
    const side = el("aside", { className: "sql-side" });
    const snippetName = el("input", { placeholder: "snippet name", id: "snippet-name" });
    const save = el("form", { className: "toolbar" }, snippetName, el("button", { type: "submit", className: "small" }, "Save query"));
    save.addEventListener("submit", (e) => {
      e.preventDefault();
      if (!snippetName.value.trim() || !query.value.trim()) return;
      const snippets = stored<{ name: string; sql: string }[]>("kilnbase-studio-snippets", []).filter((s) => s.name !== snippetName.value.trim());
      store("kilnbase-studio-snippets", [{ name: snippetName.value.trim(), sql: query.value }, ...snippets]);
      snippetName.value = ""; toast("Saved in this browser"); renderSide();
    });
    const pick = (sql: string) => { query.value = sql; query.focus(); };
    function renderSide(): void {
      const snippets = stored<{ name: string; sql: string }[]>("kilnbase-studio-snippets", []);
      const history = stored<string[]>("kilnbase-studio-history", []);
      side.replaceChildren(
        el("h3", {}, "Saved"), snippets.length ? el("div", { className: "list" }, ...snippets.map((s) => el("div", { className: "list-row" },
          button(s.name, () => pick(s.sql), "link"),
          button("×", () => { store("kilnbase-studio-snippets", snippets.filter((x) => x.name !== s.name)); renderSide(); }, "small")))) : hint("Save a query to keep it here."),
        el("h3", {}, "Templates"), el("div", { className: "list" }, ...SQL_TEMPLATES.map(([n, s]) => button(n, () => pick(s), "link"))),
        el("h3", {}, "History"), history.length ? el("div", { className: "list" }, ...history.map((s) => button(s.split("\n")[0]!.slice(0, 60) || "…", () => pick(s), "link"))) : hint("Queries you run appear here."));
    }
    renderSide();
    return [
      hint("Runs as the database superuser in one transaction (15 s limit). Schema changes made here are not recorded in db/migrations; ",
        "use `kilnbase migrate new` for changes you want to keep. Saved queries and history stay in this browser."),
      el("div", { className: "sql-layout" }, el("div", {}, form, save, result), side),
    ];
  },

  async storage(sub) {
    const [buckets, connect, policies] = await Promise.all([api<Bucket[]>("/api/buckets"), api<Connect>("/api/connect"), api<StoragePolicy[]>("/api/storage/policies")]);
    const browser = el("div");

    function settingsForm(b: Bucket): HTMLElement {
      const isPublic = el("input", { type: "checkbox", checked: b.public });
      const limit = el("input", { type: "number", min: "1", value: b.file_size_limit === null ? "" : String(b.file_size_limit), placeholder: "no limit" });
      const mime = el("input", { value: (b.allowed_mime_types ?? []).join(", "), placeholder: "image/*, application/pdf (empty: any)" });
      const msg = el("p", { className: "hint" });
      const form = el("form", { className: "builder" }, el("h3", {}, `Settings of ${b.id}`),
        el("label", {}, isPublic, " Public (anyone with the URL can read files)"),
        field("Max file size", limit, "bytes"), field("Allowed MIME types", mime),
        el("button", { type: "submit" }, "Save"), button("Cancel", () => open(b.id, "")),
        button("Delete bucket", async () => {
          if (!(await confirmDialog(`Delete bucket ${b.id}?`, "Only an empty bucket can be deleted.", { confirmLabel: "Delete bucket", danger: true }))) return;
          api(`/api/buckets/${encodeURIComponent(b.id)}/delete`, {}).then(() => { toast("Bucket deleted"); void show("storage"); }).catch((err: unknown) => fail(err, msg));
        }, "danger"), msg);
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        const types = mime.value.split(",").map((t) => t.trim()).filter(Boolean);
        api(`/api/buckets/${encodeURIComponent(b.id)}/update`, { public: isPublic.checked, file_size_limit: limit.value ? Number(limit.value) : null, allowed_mime_types: types.length ? types : null })
          .then(() => { toast("Saved"); void show(`storage/${b.id}`); }).catch((err: unknown) => fail(err, msg));
      });
      return form;
    }

    function open(bucket: string, prefix: string): void {
      const q = (name: string) => `name=${encodeURIComponent(name)}`;
      const base = `/api/buckets/${encodeURIComponent(bucket)}`;
      const info = buckets.find((b) => b.id === bucket)!;
      history.replaceState(null, "", `#storage/${bucket}`);
      browser.replaceChildren(skeleton());
      api<StoredObject[]>(`${base}/objects?prefix=${encodeURIComponent(prefix)}`).then((items) => {
        // Breadcrumbs: bucket / folder / folder
        const parts = prefix.split("/").filter(Boolean);
        const crumbs: HTMLElement[] = [button(bucket, () => open(bucket, ""), "link")];
        parts.forEach((p, i) => crumbs.push(el("span", { className: "sep" }, "/"), button(p, () => open(bucket, parts.slice(0, i + 1).join("/") + "/"), "link")));

        const file = el("input", { type: "file", id: "upload", multiple: true });
        const msg = el("span", { className: "hint" });
        file.addEventListener("change", () => {
          const files = [...(file.files ?? [])];
          msg.textContent = `Uploading ${files.length} file(s)…`;
          Promise.all(files.map((f) => request(`${base}/object?${q(prefix + f.name)}`, {
            method: "POST", body: f, headers: { "Content-Type": f.type || "application/octet-stream" },
          }))).then(() => { toast(`Uploaded ${files.length} file(s)`); open(bucket, prefix); }).catch((err: unknown) => fail(err, msg));
        });
        const folderName = el("input", { placeholder: "new folder", id: "new-folder" });
        const folderForm = el("form", { className: "toolbar inline" }, folderName, el("button", { type: "submit", className: "small" }, "Open folder"));
        folderForm.addEventListener("submit", (e) => { e.preventDefault(); if (folderName.value.trim()) open(bucket, prefix + folderName.value.trim().replace(/\/+$/, "") + "/"); });

        const rows = items.map((o) => {
          const name = el("td", {});
          const actions = el("td", { className: "actions" });
          const path = prefix + o.name;
          if (o.folder) {
            name.append(button([icon("folder"), o.name], () => open(bucket, path), "link folder"));
          } else {
            name.append(el("span", { className: "folder" }, icon("file"), o.name));
            const link = info.public
              ? copyButton(`${connect.url}/storage/v1/object/public/${encodeURIComponent(bucket)}/${path.split("/").map(encodeURIComponent).join("/")}`, "Copy URL")
              : button("Signed URL", () => api<{ public_url: string }>(`${base}/sign?${q(path)}`, { expires_in: 3600 })
                  .then((r) => navigator.clipboard.writeText(r.public_url)).then(() => toast("Signed URL (1 hour) copied")).catch((err: unknown) => fail(err, msg)));
            const dl = button("Download", () => {
              request(`${base}/object?${q(path)}`).then((r) => r.blob()).then((blob) => {
                const a = el("a", { href: URL.createObjectURL(blob), download: o.name });
                a.click();
                setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
              }).catch((err: unknown) => fail(err, msg));
            });
            const del = button("Delete", async () => {
              if (!(await confirmDialog(`Delete ${o.name}?`, `${bucket}/${path} is removed for good.`, { confirmLabel: "Delete file", danger: true }))) return;
              request(`${base}/object/delete?${q(path)}`, { method: "POST" })
                .then(() => { toast("File deleted"); open(bucket, prefix); }).catch((err: unknown) => fail(err, msg));
            }, "danger");
            actions.append(link, dl, del);
          }
          return el("tr", {}, name, el("td", {}, o.mime_type ?? ""), el("td", {}, size(o.size)),
            el("td", { title: o.updated_at }, when(o.updated_at)), actions);
        });
        browser.replaceChildren(
          el("div", { className: "toolbar" }, el("span", { className: "crumbs" }, ...crumbs),
            el("label", { htmlFor: "upload", className: "button" }, icon("upload"), "Upload files"), file,
            folderForm, button("Settings", () => browser.replaceChildren(settingsForm(info))), msg),
          prefix && !items.length ? hint("A folder exists once it holds a file: upload one here.") : "",
          rows.length
            ? grid(["name", "type", "size", "updated", ""], rows, "")
            : emptyState(icon("folder"), "This folder is empty", "Upload files to add them here."),
          items.length === 500 ? hint("Showing the first 500 entries.") : "");
      }).catch((err: unknown) => fail(err, browser));
    }

    const list = el("div", { className: "buckets" }, ...buckets.map((b) => {
      const btn = el("button", { type: "button" },
        el("strong", {}, b.id), el("br"),
        el("small", {}, `${b.public ? "public" : "private"} · ${b.objects} file(s) · ${size(b.bytes)}`));
      btn.addEventListener("click", () => {
        for (const other of list.querySelectorAll("button")) other.removeAttribute("aria-current");
        btn.setAttribute("aria-current", "page");
        open(b.id, "");
      });
      if (b.id === sub) { btn.setAttribute("aria-current", "page"); open(b.id, ""); }
      return btn;
    }));

    const id = el("input", { id: "bucket-id", required: true, pattern: "[a-z0-9][a-z0-9._\\-]{0,62}", placeholder: "avatars" });
    const isPublic = el("input", { type: "checkbox", id: "bucket-public" });
    const msg = el("p", { className: "hint" });
    const create = el("form", {},
      el("label", { htmlFor: "bucket-id" }, "New bucket"), id,
      el("label", { htmlFor: "bucket-public" }, isPublic, " Public (anyone with the URL can read files)"),
      el("button", { type: "submit" }, "Create"), msg);
    create.addEventListener("submit", (e) => {
      e.preventDefault();
      api("/api/buckets", { id: id.value, public: isPublic.checked })
        .then(() => show(`storage/${id.value}`)).catch((err: unknown) => fail(err, msg));
    });
    const policyHolder = el("div");
    const policyTable = grid(["name", "table", "command", "roles", "using", "check", ""], policyRows("storage.objects", policies.filter((p) => p.table === "objects"), () => show(`storage/${sub}`)), "No storage policies: API users cannot read or write files (service keys can).", "shield");
    return [
      hint("Files are read and written as service_role; storage policies apply to API users, not here."),
      create,
      buckets.length ? list : emptyState(icon("folder"), "No buckets yet", "Create one above to start storing files."),
      browser,
      el("h2", {}, "Storage policies ", button("New policy", () => policyHolder.replaceChildren(policyForm("storage.objects", () => show(`storage/${sub}`))), "small")),
      hint("Policies on storage.objects decide who may list, download, upload and delete through the API; `bucket_id`, `name` and `owner` are the columns to check."),
      policyHolder, policyTable,
    ];
  },

  async database() {
    const info = await api<DatabaseInfo>("/api/database");
    const msg = el("p", { className: "hint" });
    const stat = (label: string, value: string) => el("div", { className: "stat" }, el("small", {}, label), el("strong", {}, value));
    const search = el("input", { type: "search", id: "ext-search", placeholder: "filter extensions…" });
    const body = el("tbody");
    const render = () => body.replaceChildren(...info.extensions
      .filter((x) => !search.value || `${x.name} ${x.comment ?? ""}`.toLowerCase().includes(search.value.toLowerCase()))
      .map((x) => {
        const on = x.installed_version !== null;
        const b = button(on ? "Disable" : "Enable", async () => {
          if (on && !(await confirmDialog(`Disable ${x.name}?`, "The extension is dropped. If anything depends on it, this fails and nothing changes.", { confirmLabel: "Disable", danger: true }))) return;
          api(`/api/extensions/${encodeURIComponent(x.name)}/${on ? "disable" : "enable"}`, {})
            .then(() => { toast(`${x.name} ${on ? "disabled" : "enabled"}`); void show("database"); }).catch((err: unknown) => fail(err, msg));
        }, on ? "danger" : "");
        b.disabled = x.name === "plpgsql";
        return el("tr", {},
          el("td", {}, el("strong", {}, x.name)),
          el("td", {}, on ? badge(`${x.installed_version} in ${x.schema}`, "ok") : el("span", { className: "hint" }, x.default_version)),
          el("td", {}, x.comment ?? ""),
          el("td", { className: "actions" }, b));
      }));
    search.addEventListener("input", render);
    render();
    return [
      el("div", { className: "stats" },
        stat("Postgres", info.version),
        stat("Size", size(info.bytes)),
        stat("Connections", `${info.connections} / ${info.max_connections}`),
        stat("Tables in public", String(info.tables)),
        stat("Up since", when(info.started_at))),
      el("div", { className: "toolbar" }, button("Schema →", () => show("schema")), button("Performance →", () => show("performance")), button("Advisors →", () => show("advisors")), button("Migrations →", () => show("migrations")), button("Settings →", () => show("settings"))),
      el("h2", {}, "Extensions"),
      hint("Changes here are not recorded in db/migrations; add the same `create extension` to a migration to keep them."),
      el("form", {}, el("label", { htmlFor: "ext-search" }, "Filter"), search),
      msg,
      el("div", { className: "scroll" }, el("table", {},
        el("thead", {}, el("tr", {}, ...["name", "version", "description", ""].map((h) => el("th", {}, h)))), body)),
    ];
  },

  async logs(sub) {
    const service = el("select", { id: "log-service" }, option("", "All services"), ...["core", "auth", "functions", "studio"].map((s) => option(s)));
    if (sub) service.value = sub;
    const level = el("select", { id: "log-level" },
      ...[["", "All levels"], ["info", "Info and above"], ["warning", "Warnings and errors"], ["error", "Errors only"]]
        .map(([v, t]) => option(v!, t!)));
    const search = el("input", { type: "search", id: "log-search", placeholder: "text, path, status…" });
    const result = el("div");
    const load = () => {
      const params = new URLSearchParams({ service: service.value, level: level.value, q: search.value, limit: "300" });
      api<{ entries: Row[]; services: string[] }>(`/api/logs?${params}`)
        .then((r) => {
          if (r.services.length === 0) {
            result.replaceChildren(hint("No log files yet. Services write them to their log volumes once started with this version."));
            return;
          }
          const rows = r.entries.map((e) => {
            const { ts, level: lvl, service: svc, msg, ...extra } = e;
            const lv = String(lvl ?? "");
            const kind = lv === "error" || lv === "critical" ? "error" : lv === "warning" ? "warning" : "";
            const detail = Object.keys(extra).length
              ? el("code", { className: "log-extra" }, Object.entries(extra).map(([k, v]) => `${k}=${text(v)}`).join("  "))
              : "";
            return el("tr", {},
              el("td", { className: "nowrap", title: when(ts) }, when(ts, true)),
              el("td", {}, badge(String(svc ?? ""))),
              el("td", {}, badge(lv, kind)),
              el("td", { className: "log-msg" }, String(msg ?? ""), detail));
          });
          result.replaceChildren(rows.length ? grid(["time", "service", "level", "message"], rows, "") : hint("Nothing matches."));
        })
        .catch((err: unknown) => fail(err, result));
    };
    const form = el("form", {}, service, level, search, el("button", { type: "submit" }, "Filter"), button([icon("refresh"), "Refresh"], load));
    form.addEventListener("submit", (e) => { e.preventDefault(); load(); });
    service.addEventListener("change", load);
    level.addEventListener("change", load);
    load();
    return [form, result];
  },

  async connect() {
    const info = await api<Connect>("/api/connect");
    const kv = (label: string, value: string) => el("div", { className: "kv" },
      el("strong", {}, label), el("code", { className: "secretish" }, value), copyButton(value));
    const js = `import { createClient } from "kilnbase";\n\nconst kb = createClient("${info.url}", "${info.anon_key}");\nconst { data, error } = await kb.from("todos").select();`;
    const py = `from kilnbase import create_client\n\nkb = create_client("${info.url}", "${info.anon_key}")\nrows = kb.from_("todos").select().execute()`;
    const curl = `curl "${info.url}/rest/v1/todos?select=*" -H "apikey: ${info.anon_key}"`;
    return [
      hint("The anon key is meant for browsers and apps; row level security decides what it can reach. Never ship the service_role key."),
      panel(kv("API URL", info.url), kv("anon key", info.anon_key)),
      ...[["JavaScript", js], ["Python", py], ["curl", curl]].flatMap(([title, code]) => [
        el("h2", {}, title!, " ", copyButton(code!)), pre(code!)]),
      el("h2", {}, "More"), el("div", { className: "toolbar" }, button("API docs per table →", () => show("apidocs")), button("Project settings →", () => show("settings"))),
    ];
  },

  async viewas() {
    const [tables, users] = await Promise.all([api<TableInfo[]>("/api/tables"), api<User[]>("/api/users")]);
    const tableSelect = el("select", { id: "va-table", required: true }, ...tables.map((t) => option(t.name)));
    const userSelect = el("select", { id: "va-user" }, option("", "anon (no user)"),
      ...users.map((u) => option(u.id, u.email ?? u.phone ?? `${u.id} (anonymous)`)));
    const result = el("div");
    const form = el("form", {},
      el("label", { htmlFor: "va-table" }, "Table"), tableSelect,
      el("label", { htmlFor: "va-user" }, "as"), userSelect,
      el("button", { type: "submit" }, "Show rows"));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      result.replaceChildren(skeleton());
      api<{ role: string; claims: Row; denied: boolean; rows: Row[] }>("/api/view-as", { table: tableSelect.value, user_id: userSelect.value || null })
        .then((r) => result.replaceChildren(
          el("p", {}, `Role ${r.role}. `, r.denied
            ? el("span", { className: "error" }, "Permission denied: the API answers this request with an error.")
            : `${r.rows.length} row(s), exactly what the REST API returns for this caller (first 50).`),
          table(r.rows),
          details("Claims used (auth.jwt())", JSON.stringify(r.claims, null, 2))))
        .catch((err: unknown) => fail(err, result));
    });
    return [hint("Runs the query as that user, with the claims their access token carries, and rolls back."), form, result];
  },

  async users() {
    const result = el("div");
    const search = el("input", { type: "search", placeholder: "email or phone contains…", id: "user-search" });
    const act = async (u: User, action: string, question: string) => {
      const danger = action !== "confirm-email";
      if (!(await confirmDialog(u.email ?? u.phone ?? "Anonymous user", question, { confirmLabel: action === "delete" ? "Delete user" : action === "sign-out" ? "Sign out everywhere" : "Confirm email", danger }))) return;
      api(`/api/users/${u.id}/${action}`, {}).then(() => { toast("Done"); void load(); }).catch((err: unknown) => fail(err, result));
    };
    const row = (u: User) => {
      const buttons: HTMLButtonElement[] = [button("Open", () => show(`user/${u.id}`))];
      if (u.email && !u.email_confirmed_at) buttons.push(button("Confirm email", () => act(u, "confirm-email", `Mark ${u.email} as confirmed?`)));
      if (u.active_sessions > 0) buttons.push(button("Sign out", () => act(u, "sign-out", "End all sessions? Refresh tokens stop working now; access tokens already issued stay valid for up to an hour.")));
      buttons.push(button("Delete", () => act(u, "delete", `Delete ${u.email ?? u.phone ?? u.id} and everything linked to the account? This cannot be undone.`), "danger"));
      return el("tr", {},
        el("td", {}, button(u.email ?? u.phone ?? (u.is_anonymous ? "anonymous" : u.id), () => show(`user/${u.id}`), "link")),
        el("td", {}, u.email_confirmed_at ? badge("confirmed", "ok") : badge("unconfirmed")),
        el("td", { title: u.last_sign_in_at ?? "" }, u.last_sign_in_at ? when(u.last_sign_in_at) : "never"),
        el("td", {}, String(u.active_sessions)),
        el("td", { title: u.created_at }, when(u.created_at)),
        el("td", { title: u.id }, el("code", {}, `${u.id.slice(0, 8)}…`)),
        el("td", { className: "actions" }, ...buttons));
    };
    const load = () => api<User[]>(`/api/users?search=${encodeURIComponent(search.value)}`)
      .then((users) => result.replaceChildren(grid(["email / phone", "status", "last sign-in", "sessions", "created", "id", ""], users.map(row), "No users found", "users")))
      .catch((err: unknown) => fail(err, result));
    const form = el("form", {}, el("label", { htmlFor: "user-search" }, "Search"), search, el("button", { type: "submit" }, "Find"),
      button("Sessions →", () => show("sessions"), "small"), button("Auth settings →", () => show("authsettings"), "small"));
    form.addEventListener("submit", (e) => { e.preventDefault(); void load(); });

    const email = el("input", { type: "email", id: "new-email", required: true, placeholder: "user@example.com" });
    const password = el("input", { type: "password", id: "new-password", autocomplete: "new-password", placeholder: "empty: link / code / provider only" });
    const confirmed = el("input", { type: "checkbox", id: "new-confirmed", checked: true });
    const msg = el("p", { className: "hint" });
    const create = el("form", {},
      el("label", { htmlFor: "new-email" }, "New user"), email,
      el("label", { htmlFor: "new-password" }, "Password"), password,
      el("label", { htmlFor: "new-confirmed" }, confirmed, " Email confirmed"),
      el("button", { type: "submit" }, "Create"), msg);
    create.addEventListener("submit", (e) => {
      e.preventDefault();
      api<User>("/api/users", { email: email.value, password: password.value || null, email_confirmed: confirmed.checked })
        .then(() => { toast(`Created ${email.value}`); email.value = ""; password.value = ""; msg.textContent = ""; void load(); })
        .catch((err: unknown) => fail(err, msg));
    });
    void load();
    return [form, create, result];
  },

  async webhooks() {
    const [hooks, deliveries, tables] = await Promise.all([
      api<Webhook[]>("/api/webhooks"), api<Delivery[]>("/api/webhook-deliveries"), api<TableInfo[]>("/api/tables"),
    ]);
    const msg = el("p", { className: "hint" });
    const act = async (path: string, question?: string) => {
      if (question && !(await confirmDialog("Delete webhook?", question, { confirmLabel: "Delete", danger: true }))) return;
      api(path, {}).then(() => { toast("Done"); void show("webhooks"); }).catch((err: unknown) => fail(err, msg));
    };
    const hookRows = hooks.map((w) => el("tr", {},
      el("td", {}, w.name), el("td", {}, el("code", {}, w.table)), el("td", {}, w.events.join(", ")),
      el("td", {}, el("code", {}, w.host)),
      el("td", {}, w.enabled ? badge("on", "ok") : badge("off")),
      el("td", {}, `${w.pending} pending`, w.failed ? el("span", { className: "error" }, ` · ${w.failed} failed`) : ""),
      el("td", { className: "actions" },
        button(w.enabled ? "Disable" : "Enable", () => act(`/api/webhooks/${encodeURIComponent(w.name)}/${w.enabled ? "disable" : "enable"}`)),
        button("Delete", () => act(`/api/webhooks/${encodeURIComponent(w.name)}/delete`, `Delete webhook ${w.name} and its delivery log?`), "danger"))));
    const deliveryRows = deliveries.map((d) => el("tr", {},
      el("td", {}, String(d.id)), el("td", {}, d.webhook),
      el("td", {}, badge(d.status, d.status === "failed" ? "error" : d.status === "delivered" ? "ok" : "")),
      el("td", {}, String(d.attempts)), el("td", {}, d.last_status === null ? "" : String(d.last_status)),
      el("td", {}, el("code", {}, d.last_error ?? "")),
      el("td", { title: d.created_at }, when(d.created_at)),
      el("td", { className: "actions" }, d.status === "failed" ? button("Retry", () => act(`/api/webhook-deliveries/${d.id}/retry`)) : "")));

    const name = el("input", { id: "hook-name", required: true, placeholder: "new-orders" });
    const target = el("select", { id: "hook-table" }, ...tables.map((t) => option(`public.${t.name}`, t.name)));
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
    return [
      create, secret, msg,
      el("h2", {}, "Webhooks"),
      grid(["name", "table", "events", "target", "", "queue", ""], hookRows, "No webhooks yet.", "bolt"),
      el("h2", {}, "Newest deliveries"),
      grid(["id", "webhook", "status", "attempts", "HTTP", "last error", "queued", ""], deliveryRows, "No deliveries yet.", "bolt"),
    ];
  },

  async queues() {
    const info = await api<{ enabled: boolean; queues: Queue[] }>("/api/queues");
    const msg = el("p", { className: "hint" });
    if (!info.enabled) {
      const enable = button("Enable pgmq", () => api("/api/extensions/pgmq/enable", {}).then(() => { toast("pgmq enabled"); void show("queues"); }).catch((err: unknown) => fail(err, msg)));
      return [emptyState(icon("inbox"), "pgmq is not enabled", "Queues need the pgmq extension."), enable, msg];
    }
    const messages = el("div");
    const act = async (name: string, action: string, title: string, question: string) => {
      if (!(await confirmDialog(title, question, { confirmLabel: action === "delete" ? "Delete" : "Purge", danger: true }))) return;
      api(`/api/queues/${encodeURIComponent(name)}/${action}`, {}).then(() => { toast("Done"); void show("queues"); }).catch((err: unknown) => fail(err, msg));
    };
    const browse = async (name: string) => {
      const list = await api<QueueMessage[]>(`/api/queues/${encodeURIComponent(name)}/messages`);
      const body = el("textarea", { id: "queue-message", rows: 3, spellcheck: false, value: '{"hello": "world"}' });
      const sendMessage = el("div");
      const send = el("form", {}, el("label", { htmlFor: "queue-message" }, `Send to ${name} (JSON)`), body, el("button", { type: "submit" }, "Send"));
      send.addEventListener("submit", (e) => {
        e.preventDefault();
        let parsed: Json;
        try { parsed = JSON.parse(body.value) as Json; } catch { return fail(new Error("The message is not valid JSON."), sendMessage); }
        api<{ msg_id: number }>(`/api/queues/${encodeURIComponent(name)}/messages`, parsed)
          .then((r) => { toast(`Message ${r.msg_id} sent`); void browse(name); })
          .catch((err: unknown) => fail(err, sendMessage));
      });
      const rows = list.map((m) => el("tr", {},
        el("td", {}, String(m.msg_id)), el("td", {}, String(m.read_ct)),
        el("td", { title: m.enqueued_at }, when(m.enqueued_at)),
        el("td", { title: m.vt }, Date.parse(m.vt) > Date.now() ? el("span", { className: "hint" }, "hidden until " + when(m.vt, true)) : "visible"),
        el("td", {}, el("code", {}, m.message))));
      messages.replaceChildren(
        el("h2", {}, `Messages in ${name}`),
        hint("The oldest 50, peeked: reading them here neither hides them nor counts as a read."),
        grid(["id", "reads", "enqueued", "visibility", "message"], rows, "The queue is empty.", "inbox"),
        send, sendMessage);
    };
    const queueRows = info.queues.map((q) => el("tr", {},
      el("td", {}, q.name), el("td", {}, String(q.queue_length)), el("td", {}, String(q.total_messages)),
      el("td", {}, q.oldest_msg_age_sec === null ? "" : `${q.oldest_msg_age_sec} s`),
      el("td", { title: q.created_at }, when(q.created_at)),
      el("td", { className: "actions" },
        button("Messages", () => browse(q.name).catch((err: unknown) => fail(err, msg))),
        button("Purge", () => act(q.name, "purge", "Purge queue?", `Delete every message in ${q.name}?`)),
        button("Delete", () => act(q.name, "delete", "Delete queue?", `Drop ${q.name}, its messages and its archive?`), "danger"))));
    const name = el("input", { id: "queue-name", required: true, pattern: "[a-z0-9_]{1,47}", placeholder: "emails" });
    const formMessage = el("div");
    const create = el("form", {}, el("label", { htmlFor: "queue-name" }, "New queue"), name, el("button", { type: "submit" }, "Create"));
    create.addEventListener("submit", (e) => {
      e.preventDefault();
      api("/api/queues", { name: name.value }).then(() => { toast(`Queue ${name.value} created`); void show("queues"); }).catch((err: unknown) => fail(err, formMessage));
    });
    return [
      create, formMessage, msg,
      el("h2", {}, "Queues"),
      grid(["name", "waiting", "sent in total", "oldest", "created", ""], queueRows, "No queues yet.", "inbox"),
      messages,
    ];
  },

  async cron() {
    const info = await api<CronInfo>("/api/cron");
    const msg = el("p", { className: "hint" });
    if (!info.enabled) {
      const enable = button("Enable pg_cron", () => api("/api/extensions/pg_cron/enable", {}).then(() => { toast("pg_cron enabled"); void show("cron"); }).catch((err: unknown) => fail(err, msg)));
      return [emptyState(icon("clock"), "pg_cron is not enabled", "Scheduled jobs need the pg_cron extension."), enable, msg];
    }
    const act = async (name: string, action: string) => {
      if (action === "delete" && !(await confirmDialog("Delete job?", `Unschedule ${name}? Its run history is kept.`, { confirmLabel: "Delete", danger: true }))) return;
      api(`/api/cron/${encodeURIComponent(name)}/${action}`, {}).then(() => { toast("Done"); void show("cron"); }).catch((err: unknown) => fail(err, msg));
    };
    const status = (s: string | null) => badge(s ?? "never run", s === "failed" ? "error" : s === "succeeded" ? "ok" : "");
    const jobRows = info.jobs.map((j) => {
      const actions = el("td", { className: "actions" });
      // Jobs scheduled without a name (cron.schedule(schedule, command)) are managed in SQL.
      if (j.name !== null) {
        const n = j.name;
        actions.append(button(j.active ? "Disable" : "Enable", () => act(n, j.active ? "disable" : "enable")), button("Delete", () => act(n, "delete"), "danger"));
      }
      return el("tr", {},
        el("td", {}, j.name ?? `#${j.jobid}`), el("td", {}, el("code", {}, j.schedule)),
        el("td", {}, el("code", {}, j.command)), el("td", {}, j.username),
        el("td", {}, j.active ? badge("on", "ok") : badge("off")),
        el("td", { title: j.last_run ?? "" }, status(j.last_status), j.last_run ? ` · ${when(j.last_run)}` : ""),
        actions);
    });
    const runRows = info.runs.map((r) => el("tr", {},
      el("td", {}, String(r.runid)), el("td", {}, r.job), el("td", {}, status(r.status)),
      el("td", {}, el("code", {}, r.return_message ?? "")),
      el("td", { title: r.start_time ?? "" }, r.start_time ? when(r.start_time) : ""),
      el("td", {}, r.start_time && r.end_time ? `${Date.parse(r.end_time) - Date.parse(r.start_time)} ms` : "")));
    const name = el("input", { id: "cron-name", required: true, placeholder: "nightly-cleanup" });
    const schedule = el("input", { id: "cron-schedule", required: true, placeholder: "0 3 * * *" });
    const command = el("textarea", { id: "cron-command", rows: 3, required: true, spellcheck: false, placeholder: "delete from public.sessions where expires_at < now();" });
    const formMessage = el("div");
    const create = el("form", {},
      el("label", { htmlFor: "cron-name" }, "New job"), name,
      el("label", { htmlFor: "cron-schedule" }, "schedule (cron, UTC, or \"30 seconds\")"), schedule,
      el("label", { htmlFor: "cron-command" }, "SQL"), command,
      el("button", { type: "submit" }, "Schedule"));
    create.addEventListener("submit", (e) => {
      e.preventDefault();
      api("/api/cron", { name: name.value, schedule: schedule.value, command: command.value })
        .then(() => { toast(`Job ${name.value} scheduled`); void show("cron"); }).catch((err: unknown) => fail(err, formMessage));
    });
    return [
      create, formMessage,
      hint("Jobs created here run as the database superuser, like the SQL editor."),
      msg,
      el("h2", {}, "Jobs"),
      grid(["name", "schedule", "command", "runs as", "", "last run", ""], jobRows, "No jobs yet.", "clock"),
      el("h2", {}, "Newest runs"),
      grid(["run", "job", "status", "message", "started", "took"], runRows, "No runs yet.", "clock"),
    ];
  },

  ...databaseViews,
  ...authViews,
  ...platformViews,
};

const SUBTITLES: Record<string, string> = {
  overview: "This project at a glance.",
  tables: "Which tables the API serves, and the policies that decide who sees which rows.",
  data: "Browse, filter and edit rows; create tables and columns; import and export CSV.",
  sql: "Run SQL against the database.",
  schema: "Everything in the public schema: tables, functions, triggers, indexes, types, views and roles.",
  performance: "What the database is doing now, and which queries cost the most.",
  advisors: "Security and performance findings, the same checks as `kilnbase doctor`.",
  migrations: "Which platform and project migrations this database has.",
  database: "Postgres at a glance, and its extensions.",
  users: "Everyone who can sign in.",
  user: "One account: identities, factors, sessions.",
  sessions: "Every active session.",
  authsettings: "How people can sign in to this project, as configured in .env.",
  viewas: "See a table exactly as one user, or anon, sees it through the API.",
  storage: "Buckets, the files in them, and who may reach them.",
  functions: "The project's functions: source, a test call, and where their logs are.",
  realtime: "Which tables publish changes, channel authorisation, and a live inspector.",
  graphql: "Query the GraphQL API as a visitor or as a server.",
  queues: "Message queues, with pgmq.",
  cron: "SQL that runs on a schedule, with pg_cron.",
  webhooks: "HTTP calls fired by table changes, and their delivery log.",
  reports: "Requests, errors and latency over the last day; sign-ups over two weeks.",
  logs: "Recent log lines from the Kilnbase services.",
  apidocs: "How to call the API for each table, with your project's URL and anon key.",
  connect: "What an app needs to talk to this project.",
  settings: "Keys, database, services, backups.",
};
// Pages reached from another page highlight that page in the sidebar.
const PARENT: Record<string, string> = { user: "users" };

async function show(target: string): Promise<void> {
  let [name = "overview", ...rest] = target.split("/");
  const sub = decodeURIComponent(rest.join("/"));
  if (!(name in views)) name = "overview";
  const navName = PARENT[name] ?? name;
  for (const b of document.querySelectorAll<HTMLButtonElement>("#nav [data-view]")) {
    if (b.dataset.view === navName) {
      b.setAttribute("aria-current", "page");
      $("page-title").textContent = b.textContent?.trim() ?? "";
    } else b.removeAttribute("aria-current");
  }
  if (PARENT[name]) $("page-title").textContent = name === "user" ? "User" : name;
  $("page-sub").textContent = SUBTITLES[name] ?? "";
  document.title = `${$("page-title").textContent} · Kilnbase Studio`;
  const hash = `#${name}${sub ? `/${encodeURIComponent(sub)}` : ""}`;
  if (location.hash !== hash) history.replaceState(null, "", hash);
  view.replaceChildren(skeleton());
  try {
    view.replaceChildren(...(await views[name]!(sub)));
  } catch (err) {
    fail(err, view);
  }
}

function signIn(): void {
  $("login-screen").hidden = true;
  $("app").hidden = false;
  void show(location.hash.slice(1) || "overview");
}

function signOut(message = ""): void {
  sessionStorage.removeItem(KEY);
  view.replaceChildren();
  $("app").hidden = true;
  $("login-screen").hidden = false;
  $("login-error").textContent = message;
}

nav.show = show;
nav.signOut = signOut;

$<HTMLFormElement>("login").addEventListener("submit", (e) => {
  e.preventDefault();
  sessionStorage.setItem(KEY, $<HTMLInputElement>("key").value.trim());
  $<HTMLInputElement>("key").value = "";
  signIn();
});
for (const b of document.querySelectorAll<HTMLButtonElement>("#nav [data-view]")) {
  b.addEventListener("click", () => void show(b.dataset.view ?? "overview"));
}
window.addEventListener("hashchange", () => { if (!$("app").hidden) void show(location.hash.slice(1) || "overview"); });
// Ctrl/⌘+K: jump to a page by name.
const palette = $<HTMLInputElement>("palette");
palette.addEventListener("change", () => { if (palette.value) { void show(palette.value); palette.value = ""; } });
window.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); palette.focus(); } });
$("signout").addEventListener("click", () => signOut());
loadFont();
$("signout").before(themeButton());
if (sessionStorage.getItem(KEY)) signIn();

// Database pages: schema objects, performance, advisors, migrations.
import { confirmDialog, emptyState, toast } from "./ui";
import {
  api, badge, button, details, draftSql, el, fail, grid, hint, icon, nav, pre, quoteIdent, quoteLiteral, runSql,
  size, tabs, when,
} from "./lib";
import type { Row } from "./lib";

interface Schema {
  tables: { name: string; estimated_rows: number; bytes: number; rls: boolean; realtime: boolean; has_key: boolean; comment: string | null }[];
  functions: { name: string; args: string; returns: string; language: string; security_definer: boolean; procedure: boolean; definition: string }[];
  triggers: { name: string; table: string; enabled: boolean; definition: string }[];
  indexes: { name: string; table: string; unique: boolean; primary: boolean; bytes: number; scans: number; definition: string }[];
  enums: { name: string; values: string[] }[];
  views: { name: string; materialized: boolean; security_invoker: boolean; definition: string }[];
  roles: { name: string; superuser: boolean; login: boolean; bypass_rls: boolean; connection_limit: number; member_of: string[] }[];
  foreign_keys: { name: string; table: string; references: string; definition: string }[];
}
interface Finding { level: "fail" | "warn" | "info"; message: string }
interface Performance {
  activity: Row[]; statements_enabled: boolean; statements: Row[];
  tables: { name: string; live_rows: number | null; dead_rows: number | null; seq_scan: number | null; idx_scan: number | null; bytes: number; last_autovacuum: string | null; last_autoanalyze: string | null }[];
}

const TABS: [string, string][] = [
  ["tables", "Tables"], ["functions", "Functions"], ["triggers", "Triggers"], ["indexes", "Indexes"],
  ["enums", "Enums"], ["views", "Views"], ["relationships", "Relationships"], ["roles", "Roles"],
];

function levelBadge(level: Finding["level"]): HTMLElement {
  return badge(level === "fail" ? "fail" : level === "warn" ? "warning" : "info", level === "fail" ? "error" : level === "warn" ? "warning" : "");
}

function findings(list: Finding[], allGood: string): HTMLElement {
  if (list.length === 0) return el("div", { className: "check good" }, icon("check"), allGood);
  return el("div", { className: "checks" }, ...list.map((f) => el("div", { className: `check ${f.level === "info" ? "" : "bad"}` }, levelBadge(f.level), f.message)));
}

export const databaseViews: Record<string, (sub: string) => Promise<Node[]>> = {
  async schema(sub) {
    const s = await api<Schema>("/api/schema");
    const tab = TABS.some(([id]) => id === sub) ? sub : "tables";
    const reload = () => nav.show(`schema/${tab}`);
    const drop = (sql: string, what: string) => runSql(sql, { title: `Drop ${what}?`, confirmLabel: "Drop", danger: true, success: `Dropped ${what}` }).then((ok) => { if (ok) void reload(); });
    const ident = (name: string) => `public.${quoteIdent(name)}`;
    let body: Node[];
    switch (tab) {
      case "functions":
        body = [
          el("div", { className: "toolbar" }, button("New function", () => draftSql("create or replace function public.hello(name text)\n returns text language sql stable as $$\n  select 'hello ' || name\n$$;\n"))),
          grid(["function", "returns", "language", "", ""], s.functions.map((f) => el("tr", {},
            el("td", {}, el("strong", {}, f.name), el("code", {}, `(${f.args})`), el("br"), details("definition", f.definition)),
            el("td", {}, el("code", {}, f.returns)), el("td", {}, f.language),
            el("td", {}, f.security_definer ? badge("security definer", "warning") : "", f.procedure ? badge("procedure") : ""),
            el("td", { className: "actions" },
              button("Edit", () => draftSql(f.definition + ";\n"), "small"),
              button("Drop", () => drop(`drop ${f.procedure ? "procedure" : "function"} ${ident(f.name)}(${f.args});\n`, f.name), "danger")))),
            "No functions in public yet.", "code"),
        ];
        break;
      case "triggers":
        body = [
          hint("Triggers named kilnbase_realtime and kilnbase_webhooks are managed on the Realtime and Webhooks pages."),
          grid(["trigger", "table", "", "definition", ""], s.triggers.map((t) => el("tr", {},
            el("td", {}, el("strong", {}, t.name)), el("td", {}, el("code", {}, t.table)),
            el("td", {}, t.enabled ? badge("enabled", "ok") : badge("disabled")),
            el("td", {}, el("code", {}, t.definition)),
            el("td", { className: "actions" },
              button(t.enabled ? "Disable" : "Enable", () => runSql(`alter table ${ident(t.table)} ${t.enabled ? "disable" : "enable"} trigger ${quoteIdent(t.name)};\n`,
                { title: `${t.enabled ? "Disable" : "Enable"} ${t.name}?`, confirmLabel: t.enabled ? "Disable" : "Enable", success: "Done" }).then((ok) => { if (ok) void reload(); })),
              button("Drop", () => drop(`drop trigger ${quoteIdent(t.name)} on ${ident(t.table)};\n`, t.name), "danger")))),
            "No triggers in public.", "bolt"),
        ];
        break;
      case "indexes":
        body = [
          el("div", { className: "toolbar" }, button("New index", () => draftSql("create index concurrently if not exists todos_owner_idx on public.todos (owner);\n"))),
          grid(["index", "table", "", "size", "scans", "definition", ""], s.indexes.map((i) => el("tr", {},
            el("td", {}, el("strong", {}, i.name)), el("td", {}, el("code", {}, i.table)),
            el("td", {}, i.primary ? badge("primary key", "ok") : i.unique ? badge("unique") : ""),
            el("td", {}, size(i.bytes)), el("td", {}, String(i.scans)), el("td", {}, el("code", {}, i.definition)),
            el("td", { className: "actions" }, i.primary ? "" : button("Drop", () => drop(`drop index ${ident(i.name)};\n`, i.name), "danger")))),
            "No indexes in public.", "database"),
        ];
        break;
      case "enums":
        body = [
          el("div", { className: "toolbar" }, button("New enum", () => draftSql("create type public.status as enum ('draft', 'published', 'archived');\n"))),
          grid(["type", "values", ""], s.enums.map((e) => {
            const value = el("input", { placeholder: "new value" });
            const add = el("form", { className: "toolbar inline" }, value, el("button", { type: "submit", className: "small" }, "Add value"));
            add.addEventListener("submit", (ev) => {
              ev.preventDefault();
              if (!value.value.trim()) return;
              void runSql(`alter type ${ident(e.name)} add value ${quoteLiteral(value.value.trim())};\n`, { title: `Add ${value.value} to ${e.name}?`, confirmLabel: "Add value", success: "Value added" }).then((ok) => { if (ok) void reload(); });
            });
            return el("tr", {}, el("td", {}, el("strong", {}, e.name)), el("td", {}, ...e.values.map((v) => badge(v))),
              el("td", { className: "actions" }, add, button("Drop", () => drop(`drop type ${ident(e.name)};\n`, e.name), "danger")));
          }), "No enum types in public.", "database"),
        ];
        break;
      case "views":
        body = [
          hint("Views without security_invoker run as their owner and bypass row level security; the Advisors page flags them."),
          grid(["view", "", "definition", ""], s.views.map((v) => el("tr", {},
            el("td", {}, el("strong", {}, v.name)),
            el("td", {}, v.materialized ? badge("materialized") : "", v.security_invoker ? badge("security invoker", "ok") : v.materialized ? "" : badge("owner's rights", "warning")),
            el("td", {}, details("definition", v.definition)),
            el("td", { className: "actions" },
              v.materialized ? button("Refresh", () => runSql(`refresh materialized view ${ident(v.name)};\n`, { title: `Refresh ${v.name}?`, confirmLabel: "Refresh", success: "Refreshed" })) : "",
              button("Drop", () => drop(`drop ${v.materialized ? "materialized " : ""}view ${ident(v.name)};\n`, v.name), "danger")))),
            "No views in public.", "table"),
        ];
        break;
      case "relationships":
        body = [grid(["constraint", "table", "references", "definition"], s.foreign_keys.map((f) => el("tr", {},
          el("td", {}, el("strong", {}, f.name)), el("td", {}, el("code", {}, f.table)), el("td", {}, el("code", {}, f.references)), el("td", {}, el("code", {}, f.definition)))),
          "No foreign keys between public tables.", "table")];
        break;
      case "roles":
        body = [
          hint("anon and authenticated are what API callers run as; service_role bypasses row level security; authenticator is the API's login."),
          grid(["role", "", "member of", "connections"], s.roles.map((r) => el("tr", {},
            el("td", {}, el("strong", {}, r.name)),
            el("td", {}, r.superuser ? badge("superuser", "warning") : "", r.login ? badge("login") : "", r.bypass_rls ? badge("bypass RLS", "warning") : ""),
            el("td", {}, r.member_of.join(", ")), el("td", {}, r.connection_limit < 0 ? "unlimited" : String(r.connection_limit)))),
            "No roles.", "users"),
        ];
        break;
      default:
        body = [
          el("div", { className: "toolbar" }, button([icon("table"), "New table"], () => nav.show("data"))),
          grid(["table", "rows (est.)", "size", "", "comment", ""], s.tables.map((t) => el("tr", {},
            el("td", {}, button(t.name, () => nav.show(`data/${t.name}`), "link")),
            el("td", {}, t.estimated_rows < 0 ? "?" : t.estimated_rows.toLocaleString()), el("td", {}, size(t.bytes)),
            el("td", {}, t.rls ? badge("RLS", "ok") : badge("no RLS", "error"), " ", t.realtime ? badge("realtime", "ok") : "", " ", t.has_key ? "" : badge("no primary key", "warning")),
            el("td", {}, t.comment ?? ""),
            el("td", { className: "actions" },
              button("Rows", () => nav.show(`data/${t.name}`), "small"), button("Policies", () => nav.show("tables"), "small"),
              button("Drop", () => drop(`drop table ${ident(t.name)};\n`, t.name), "danger")))),
            "No tables in public yet.", "table"),
        ];
    }
    return [tabs("schema", TABS, tab), ...body];
  },

  async performance() {
    const p = await api<Performance>("/api/performance");
    const msg = el("p", { className: "hint" });
    const reload = () => nav.show("performance");
    const act = async (pid: number, action: string) => {
      if (!(await confirmDialog(`${action === "cancel" ? "Cancel" : "Terminate"} backend ${pid}?`, action === "cancel" ? "The running statement is cancelled; the connection stays." : "The connection is closed; its transaction is rolled back.", { confirmLabel: action === "cancel" ? "Cancel query" : "Terminate", danger: true }))) return;
      api(`/api/performance/${pid}/${action}`, {}).then(() => { toast("Done"); void reload(); }).catch((err: unknown) => fail(err, msg));
    };
    const activity = p.activity.map((a) => el("tr", {},
      el("td", {}, String(a.pid)), el("td", {}, String(a.role ?? "")), el("td", {}, String(a.application ?? "")),
      el("td", {}, badge(String(a.state ?? ""), a.state === "active" ? "ok" : "")), el("td", {}, String(a.waiting ?? "")),
      el("td", {}, typeof a.ms === "number" ? `${Math.round(a.ms)} ms` : ""),
      el("td", {}, el("code", {}, String(a.query ?? ""))),
      el("td", { className: "actions" }, button("Cancel", () => act(Number(a.pid), "cancel")), button("Terminate", () => act(Number(a.pid), "terminate"), "danger"))));
    const statements = p.statements.map((s) => el("tr", {},
      el("td", {}, String(s.calls)), el("td", {}, String(s.total_ms)), el("td", {}, String(s.mean_ms)), el("td", {}, String(s.max_ms)),
      el("td", {}, String(s.rows)), el("td", {}, String(s.role)), el("td", {}, el("code", {}, String(s.query)))));
    const tables = p.tables.map((t) => el("tr", {},
      el("td", {}, el("strong", {}, t.name)), el("td", {}, (t.live_rows ?? 0).toLocaleString()), el("td", {}, (t.dead_rows ?? 0).toLocaleString()),
      el("td", {}, (t.seq_scan ?? 0).toLocaleString()), el("td", {}, (t.idx_scan ?? 0).toLocaleString()), el("td", {}, size(t.bytes)),
      el("td", {}, t.last_autovacuum ? when(t.last_autovacuum) : "never")));
    const enable = button("Enable pg_stat_statements", () => api("/api/extensions/pg_stat_statements/enable", {}).then(() => { toast("Enabled"); void reload(); }).catch((err: unknown) => fail(err, msg)));
    return [
      el("div", { className: "toolbar" }, button([icon("refresh"), "Refresh"], reload),
        button("Reset statistics", async () => {
          if (!(await confirmDialog("Reset statistics?", "Scan counts, dead-row counts and pg_stat_statements start from zero.", { confirmLabel: "Reset", danger: true }))) return;
          api("/api/performance/reset", {}).then(() => { toast("Statistics reset"); void reload(); }).catch((err: unknown) => fail(err, msg));
        }, "danger")),
      msg,
      el("h2", {}, "Running now"),
      grid(["pid", "role", "application", "state", "waiting on", "running for", "query", ""], activity, "No other connections.", "database"),
      el("h2", {}, "Most expensive statements"),
      p.statements_enabled
        ? grid(["calls", "total ms", "mean ms", "max ms", "rows", "role", "query"], statements, "No statements recorded yet.", "chart")
        : el("div", {}, emptyState(icon("chart"), "pg_stat_statements is not enabled", "It records every statement's time and call count. It is preloaded in the Kilnbase Postgres image, so enabling the extension is enough."), enable),
      el("h2", {}, "Tables"),
      grid(["table", "live rows", "dead rows", "seq scans", "index scans", "size", "last autovacuum"], tables, "No tables in public.", "table"),
    ];
  },

  async advisors() {
    const a = await api<{ security: Finding[]; performance: Finding[] }>("/api/advisors");
    return [
      el("div", { className: "toolbar" }, button([icon("refresh"), "Run again"], () => nav.show("advisors")), button("Open SQL editor", () => nav.show("sql"))),
      el("h2", {}, "Security ", badge(`${a.security.length}`, a.security.some((f) => f.level === "fail") ? "error" : a.security.length ? "warning" : "ok")),
      findings(a.security, "No security findings: every exposed table has RLS, no view or function bypasses it, no bucket is public."),
      el("h2", {}, "Performance ", badge(`${a.performance.length}`, a.performance.some((f) => f.level === "warn") ? "warning" : "ok")),
      findings(a.performance, "No performance findings."),
      hint("The same database checks run from the command line with `kilnbase doctor`, which also audits .env."),
    ];
  },

  async migrations() {
    const m = await api<{ platform: Row[]; app: Row[] }>("/api/migrations");
    return [
      hint("Platform migrations ship with Kilnbase and are applied by the auth service at start. Project migrations live in db/migrations and are applied with `kilnbase migrate`; `kilnbase migrate new <name>` creates one."),
      el("h2", {}, `Project migrations (${m.app.length})`),
      grid(["version", "applied", "checksum"], m.app.map((r) => el("tr", {}, el("td", {}, el("strong", {}, String(r.version))), el("td", {}, when(r.applied_at)), el("td", {}, el("code", {}, String(r.checksum).slice(0, 16))))),
        "No project migrations applied yet.", "database", "Create one with `kilnbase migrate new <name>` and apply it with `kilnbase migrate`."),
      el("h2", {}, `Platform migrations (${m.platform.length})`),
      grid(["version", "checksum"], m.platform.map((r) => el("tr", {}, el("td", {}, String(r.version)), el("td", {}, el("code", {}, String(r.checksum ?? "").slice(0, 16))))), "None recorded.", "database"),
      pre("# a schema change made in Studio, kept as a migration:\nuv run kilnbase migrate new add_orders\n# paste the SQL into db/migrations/<time>_add_orders.sql, then\nuv run kilnbase migrate"),
    ];
  },
};

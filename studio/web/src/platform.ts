// Functions, realtime, GraphQL, API docs, reports and project settings.
import { emptyState, skeleton, toast } from "./ui";
import {
  api, badge, button, copyButton, details, draftSql, el, fail, field, grid, hint, icon, KEY, message, nav, option, panel,
  pre, quoteIdent, runSql, size, when,
} from "./lib";
import type { Column, Connect, Json, Row, RowsPage, TableInfo } from "./lib";

interface FunctionInfo { name: string; entry: string; language: string; bytes: number; updated_at: number; files: string[]; conflict: boolean }
interface Functions { mounted: boolean; functions: FunctionInfo[]; requirements: boolean; package: boolean }
interface Invocation { status: number; headers: Record<string, string>; body: string; truncated: boolean; ms: number }
interface Realtime { tables: { name: string; enabled: boolean; has_key: boolean }[]; authorize: string; events: number }
interface Reports {
  hours: { hour: number; ok: number; client_error: number; server_error: number }[];
  services: { service: string; requests: number; errors: number; p50_ms: number | null; p95_ms: number | null }[];
  days: { day: string; sign_ups: number; sign_ins: number }[];
  buckets: { bucket: string; files: number; bytes: number }[];
  tables: { name: string; live_rows: number | null; bytes: number }[];
}
interface Settings {
  public_url: string; anon_key: string; jwt: { alg?: string; kid?: string; issuer?: string };
  database: { host: string; port: number; name: string; user: string; version: string; settings: { name: string; setting: string; unit: string | null }[] };
  archiver: Row; services: Record<string, boolean>; logs: Record<string, number | null>; functions_mounted: boolean;
}

function kv(label: string, value: string | Node, copy?: string): HTMLElement {
  return el("div", { className: "kv" }, el("strong", {}, label), typeof value === "string" ? el("code", { className: "secretish" }, value) : value, copy ? copyButton(copy) : "");
}

/** A row of bars with a caption; heights are relative to the largest value. */
function bars(points: { label: string; values: { value: number; kind: string }[]; title: string }[]): HTMLElement {
  const max = Math.max(1, ...points.map((p) => p.values.reduce((a, v) => a + v.value, 0)));
  return el("div", { className: "bars", role: "img" }, ...points.map((p) => {
    const stack = el("div", { className: "bar", title: p.title });
    for (const v of p.values) {
      const seg = el("span", { className: `seg ${v.kind}` });
      seg.style.height = `${(v.value / max) * 100}%`;
      stack.append(seg);
    }
    return el("div", { className: "bar-col" }, stack, el("small", {}, p.label));
  }));
}

export const platformViews: Record<string, (sub: string) => Promise<Node[]>> = {
  async functions(sub) {
    const f = await api<Functions>("/api/functions");
    if (!f.mounted) return [emptyState(icon("code"), "The functions directory is not mounted", "Mount ./functions at /functions in the studio service (docker-compose.yml) to list and test functions here.")];
    if (f.functions.length === 0) return [emptyState(icon("code"), "No functions yet", "Add functions/<name>/main.py or main.ts and start the functions profile."), pre("# functions/hello/main.py\ndef handler(request):\n    return {\"hello\": request.user.get(\"sub\") or \"anon\"}\n\n# COMPOSE_PROFILES=functions docker compose up -d")];
    const current = f.functions.find((x) => x.name === sub) ?? f.functions[0]!;
    const list = el("div", { className: "buckets" }, ...f.functions.map((x) => {
      const b = el("button", { type: "button" }, el("strong", {}, x.name), el("br"), el("small", {}, `${x.language} · ${size(x.bytes)} · ${when(x.updated_at)}`));
      if (x.name === current.name) b.setAttribute("aria-current", "page");
      b.addEventListener("click", () => nav.show(`functions/${x.name}`));
      return b;
    }));
    const source = el("pre", { className: "code source" }, "Loading…");
    const fileSelect = el("select", {}, ...current.files.map((n) => option(n)));
    fileSelect.value = current.entry;
    const loadSource = () => api<{ source: string; truncated: boolean }>(`/api/functions/${current.name}/source?file=${encodeURIComponent(fileSelect.value)}`)
      .then((s) => { source.textContent = s.source + (s.truncated ? "\n… (truncated)" : ""); }).catch((err: unknown) => fail(err, source));
    fileSelect.addEventListener("change", loadSource);
    void loadSource();

    const method = el("select", {}, ...["POST", "GET", "PUT", "PATCH", "DELETE"].map((m) => option(m)));
    const query = el("input", { placeholder: "a=1&b=2" });
    const headers = el("textarea", { rows: 2, spellcheck: false, placeholder: "Content-Type: application/json" });
    const body = el("textarea", { rows: 4, spellcheck: false, value: '{"name": "world"}' });
    const caller = el("select", {}, option("anon", "as a visitor (anon key)"), option("service_role", "as a server (service_role)"));
    const result = el("div");
    const form = el("form", { className: "builder" }, el("h3", {}, `Call ${current.name}`),
      el("div", { className: "toolbar" }, method, el("code", {}, `/functions/v1/${current.name}?`), query),
      field("Headers", headers, "one per line"), field("Body", body), field("Caller", caller),
      el("button", { type: "submit" }, "Send"));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const hdrs = Object.fromEntries(headers.value.split("\n").map((l) => l.split(":")).filter((p) => p.length >= 2).map(([k, ...v]) => [k!.trim(), v.join(":").trim()]));
      if (!("Content-Type" in hdrs) && body.value.trim().startsWith("{")) hdrs["Content-Type"] = "application/json";
      result.replaceChildren(skeleton(3));
      api<Invocation>(`/api/functions/${current.name}/invoke`, { method: method.value, query: query.value, headers: hdrs, body: body.value, caller: caller.value })
        .then((r) => result.replaceChildren(
          el("p", {}, badge(`HTTP ${r.status}`, r.status < 400 ? "ok" : r.status < 500 ? "warning" : "error"), ` ${r.ms} ms`,
            r.status === 404 ? el("span", { className: "hint" }, " — not found: is KILNBASE_FUNCTIONS_URL set and the functions profile running?") : ""),
          pre(r.body + (r.truncated ? "\n… (truncated)" : "")),
          details("Response headers", Object.entries(r.headers).map(([k, v]) => `${k}: ${v}`).join("\n"))))
        .catch((err: unknown) => fail(err, result));
    });
    return [
      hint("Functions run in the functions service, one sandbox per call; calls here go through core like any client's. ",
        f.requirements ? "Python packages: functions/requirements.txt. " : "", f.package ? "npm packages: functions/package.json. " : "",
        button("Logs →", () => nav.show("logs/functions"), "link")),
      list,
      el("div", { className: "split" },
        el("div", {}, el("h2", {}, `Source `, fileSelect), source),
        el("div", {}, form, result)),
    ];
  },

  async realtime() {
    const r = await api<Realtime>("/api/realtime");
    const reload = () => nav.show("realtime");
    const tables = r.tables.map((t) => el("tr", {},
      el("td", {}, el("strong", {}, t.name)), el("td", {}, t.enabled ? badge("publishing", "ok") : t.has_key ? badge("off") : badge("no primary key", "warning")),
      el("td", { className: "actions" }, t.has_key || t.enabled ? button(t.enabled ? "Disable" : "Enable", () => runSql(`select kilnbase.${t.enabled ? "disable" : "enable"}_realtime('public.${quoteIdent(t.name)}');\n`,
        { title: `${t.enabled ? "Stop" : "Start"} publishing changes of ${t.name}?`, confirmLabel: t.enabled ? "Disable" : "Enable", success: "Done" }).then((ok) => { if (ok) void reload(); })) : "")));

    // Inspector: a server-sent stream relayed by Studio (the page may not open sockets elsewhere).
    const tableSelect = el("select", {}, option("", "no table"), ...r.tables.filter((t) => t.enabled).map((t) => option(t.name)));
    const channel = el("input", { placeholder: "channel, e.g. room:1" });
    const log = el("div", { className: "scroll inspector" });
    const status = el("span", { className: "hint" }, "Not listening.");
    let controller: AbortController | null = null;
    const stop = button("Stop", () => { controller?.abort(); controller = null; status.textContent = "Stopped."; stop.disabled = true; });
    stop.disabled = true;
    const listen = el("form", { className: "toolbar" }, tableSelect, channel, el("button", { type: "submit" }, "Listen"), stop, status);
    listen.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!tableSelect.value && !channel.value.trim()) return;
      controller?.abort();
      controller = new AbortController();
      stop.disabled = false;
      log.replaceChildren();
      status.textContent = "Listening (up to 5 minutes)…";
      try {
        const params = new URLSearchParams({ table: tableSelect.value, channel: channel.value.trim() });
        const res = await fetch(`/api/realtime/listen?${params}`, { headers: { Authorization: `Bearer ${sessionStorage.getItem(KEY) ?? ""}` }, signal: controller.signal });
        if (res.status === 401) return nav.signOut("The key was rejected.");
        if (!res.ok || !res.body) throw new Error(((await res.json().catch(() => ({}))) as { message?: string }).message ?? `HTTP ${res.status}`);
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buffer = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += value;
          const frames = buffer.split("\n\n");
          buffer = frames.pop() ?? "";
          for (const frame of frames) {
            const data = frame.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).join("");
            if (!data) continue;
            let parsed: Row;
            try { parsed = JSON.parse(data) as Row; } catch { continue; }
            const kind = String(parsed.type ?? "");
            const row = el("div", { className: "event" },
              el("span", { className: "nowrap hint" }, new Date().toLocaleTimeString()), " ",
              badge(kind === "change" ? String(parsed.op) : kind, kind === "error" ? "error" : kind === "change" || kind === "broadcast" ? "ok" : ""), " ",
              el("code", {}, JSON.stringify(parsed)));
            log.prepend(row);
            while (log.childElementCount > 200) log.lastElementChild?.remove();
            if (kind === "closed") status.textContent = "Closed: time limit reached.";
          }
        }
      } catch (err) {
        if (!(err instanceof DOMException && err.name === "AbortError")) status.textContent = message(err);
      } finally { stop.disabled = true; }
    });

    const bChannel = el("input", { placeholder: "room:1", required: true });
    const bEvent = el("input", { value: "ping", required: true });
    const bPayload = el("textarea", { rows: 2, spellcheck: false, value: '{"hello": "world"}' });
    const bMsg = el("p", { className: "hint" });
    const broadcast = el("form", { className: "builder" }, el("h3", {}, "Send a broadcast"), field("Channel", bChannel), field("Event", bEvent), field("Payload", bPayload, "JSON"), el("button", { type: "submit" }, "Send"), bMsg);
    broadcast.addEventListener("submit", (e) => {
      e.preventDefault();
      let payload: Json;
      try { payload = JSON.parse(bPayload.value || "null") as Json; } catch { return fail(new Error("The payload is not valid JSON."), bMsg); }
      api("/api/realtime/broadcast", { channel: bChannel.value, event: bEvent.value, payload }).then(() => toast("Sent")).catch((err: unknown) => fail(err, bMsg));
    });
    return [
      el("h2", {}, "Tables publishing changes"),
      hint("A subscribed client receives INSERT and UPDATE rows it may SELECT under RLS, and the primary key of DELETEs. ", `${r.events} event(s) in the ten-minute replay outbox.`),
      grid(["table", "", ""], tables, "No tables in public.", "radio"),
      el("h2", {}, "Inspector"),
      hint("Listens as service_role, so every change and every channel message is shown regardless of policies."),
      listen, log,
      el("div", { className: "split" },
        broadcast,
        el("div", {}, el("h3", {}, "Channel authorisation ", button("Edit", () => draftSql(r.authorize + ";\n"), "small")),
          hint("Broadcast and presence channels are closed until realtime.authorize allows them; it runs as the caller, so auth.uid() works."),
          details("realtime.authorize", r.authorize))),
    ];
  },

  async graphql() {
    const query = el("textarea", { rows: 10, spellcheck: false, value: sessionStorage.getItem("kilnbase-studio-graphql") ?? "{\n  __schema {\n    queryType {\n      fields { name }\n    }\n  }\n}" });
    const variables = el("textarea", { rows: 3, spellcheck: false, placeholder: '{"first": 10}' });
    const caller = el("select", {}, option("anon", "as a visitor (anon key)"), option("service_role", "as a server (service_role)"));
    const result = el("div");
    const run = () => {
      sessionStorage.setItem("kilnbase-studio-graphql", query.value);
      let vars: Row | null = null;
      try { vars = variables.value.trim() ? (JSON.parse(variables.value) as Row) : null; } catch { return fail(new Error("Variables are not valid JSON."), result); }
      result.replaceChildren(skeleton(4));
      api<unknown>("/api/graphql", { query: query.value, variables: vars, caller: caller.value })
        .then((r) => result.replaceChildren(pre(JSON.stringify(r, null, 2))))
        .catch((err: unknown) => result.replaceChildren(el("p", { className: "error" }, message(err)),
          message(err).includes("not_found") || message(err).includes("404") ? hint("The GraphQL service is not running: set KILNBASE_GRAPHQL_URL=http://graphql:4000 and start with COMPOSE_PROFILES=graphql.") : ""));
    };
    const form = el("form", { className: "sql-form" }, query, el("div", { className: "toolbar" }, el("button", { type: "submit" }, "Run"), caller, el("span", { className: "hint" }, "Ctrl+Enter runs")), field("Variables", variables));
    form.addEventListener("submit", (e) => { e.preventDefault(); run(); });
    query.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); } });
    return [hint("Queries go to /graphql/v1 through core; the same tables and policies as the REST API. Table `todos` becomes `allTodos`, `todoById` and the `createTodo` family."), form, result];
  },

  async apidocs(sub) {
    const [tables, connect] = await Promise.all([api<TableInfo[]>("/api/tables"), api<Connect>("/api/connect")]);
    const select = el("select", { id: "doc-table" }, option("", "Auth & storage"), ...tables.map((t) => option(t.name)));
    const current = tables.some((t) => t.name === sub) ? sub : "";
    select.value = current;
    select.addEventListener("change", () => nav.show(`apidocs/${select.value}`));
    const section = (title: string, code: string) => [el("h3", {}, title, " ", copyButton(code)), pre(code)];
    const url = connect.url, key = connect.anon_key;
    const head = [el("form", {}, el("label", { htmlFor: "doc-table" }, "Table"), select),
      hint("Snippets use your project URL and anon key. Signed-in users add their access token; row level security decides what each caller sees.")];
    if (!current) {
      return [...head,
        el("h2", {}, "Client"),
        ...section("JavaScript", `import { createClient } from "kilnbase";\nconst kb = createClient("${url}", "${key}");`),
        ...section("Python", `from kilnbase import create_client\nkb = create_client("${url}", "${key}")`),
        el("h2", {}, "Auth"),
        ...section("Sign up / sign in (JavaScript)", `await kb.auth.signUp({ email, password });\nconst { data, error } = await kb.auth.signInWithPassword({ email, password });\nawait kb.auth.signInWithOtp({ email });        // magic link / code\nconst oauth = await kb.auth.signInWithOAuth("github", { redirectTo: "https://app.example.com/callback" });\nawait kb.auth.signOut();`),
        ...section("curl", `curl -X POST "${url}/auth/v1/token?grant_type=password" -H "apikey: ${key}" \\\n  -H "Content-Type: application/json" -d '{"email":"a@b.c","password":"…"}'`),
        el("h2", {}, "Storage"),
        ...section("Upload & download (JavaScript)", `await kb.storage.from("avatars").upload("me.png", file);\nconst { data } = await kb.storage.from("avatars").download("me.png");\nconst url = kb.storage.from("avatars").getPublicUrl("me.png");          // public buckets\nconst { data: signed } = await kb.storage.from("avatars").createSignedUrl("me.png", 3600);\nawait kb.storage.from("avatars").remove("me.png");`),
        ...section("curl", `curl -X POST "${url}/storage/v1/object/avatars/me.png" -H "apikey: ${key}" \\\n  -H "Authorization: Bearer <access token>" -H "Content-Type: image/png" --data-binary @me.png`),
        el("h2", {}, "Realtime"),
        ...section("Subscribe (JavaScript)", `const stop = kb.realtime.subscribe("todos", (change) => console.log(change.op, change.record));\n// enable per table: select kilnbase.enable_realtime('public.todos');\nconst room = kb.realtime.channel("room:42", { onBroadcast: (event, payload) => console.log(event, payload) });\nroom.send("cursor", { x: 1, y: 2 });`),
      ];
    }
    const page = await api<RowsPage>(`/api/tables/${encodeURIComponent(current)}/rows?limit=1`);
    const cols = page.columns;
    const sample = Object.fromEntries(cols.filter((c) => !c.read_only && !c.default).slice(0, 3).map((c) => [c.name, /int|numeric|double/.test(c.type) ? 1 : /bool/.test(c.type) ? true : "…"]));
    const keyCol = page.key[0] ?? cols[0]!.name;
    const colRows = cols.map((c: Column) => el("tr", {}, el("td", {}, el("strong", {}, c.name), ...(c.primary_key ? [" ", badge("pk", "ok")] : [])), el("td", {}, el("code", {}, c.type)), el("td", {}, c.nullable ? "nullable" : "required"), el("td", {}, el("code", {}, c.default ?? ""))));
    const q = quoteIdent;
    return [...head,
      el("h2", {}, `public.${current}`), grid(["column", "type", "", "default"], colRows, "No columns"),
      el("h2", {}, "JavaScript"),
      ...section("Read", `const { data, error } = await kb.from("${current}").select().order("${keyCol}").limit(20);\nconst one = await kb.from("${current}").select().eq("${keyCol}", value).single();`),
      ...section("Insert", `const { data, error } = await kb.from("${current}").insert(${JSON.stringify(sample)}).select();`),
      ...section("Update", `await kb.from("${current}").update({ /* columns */ }).eq("${keyCol}", value);`),
      ...section("Delete", `await kb.from("${current}").delete().eq("${keyCol}", value);`),
      ...section("Subscribe", `const stop = kb.realtime.subscribe("${current}", (change) => console.log(change.op, change.record));`),
      el("h2", {}, "Python"),
      ...section("Read & insert", `rows = kb.from_("${current}").select("*").order("${keyCol}").limit(20).execute()\nkb.from_("${current}").insert(${JSON.stringify(sample)}).execute()`),
      el("h2", {}, "curl"),
      ...section("Read", `curl "${url}/rest/v1/${current}?select=*&order=${keyCol}&limit=20" -H "apikey: ${key}" \\\n  -H "Authorization: Bearer <access token>"`),
      ...section("Insert", `curl -X POST "${url}/rest/v1/${current}" -H "apikey: ${key}" -H "Authorization: Bearer <access token>" \\\n  -H "Content-Type: application/json" -H "Prefer: return=representation" -d '${JSON.stringify(sample)}'`),
      el("h2", {}, "SQL"),
      ...section("Policy for own rows", `create policy "own rows" on public.${q(current)} for all to authenticated\n  using (owner = auth.uid()) with check (owner = auth.uid());`),
    ];
  },

  async reports() {
    const r = await api<Reports>("/api/reports");
    const total = r.hours.reduce((a, h) => a + h.ok + h.client_error + h.server_error, 0);
    const hourLabel = (h: number) => new Date(h * 1000).getHours().toString().padStart(2, "0");
    const legend = el("p", { className: "hint legend" }, el("span", { className: "seg ok" }), " 2xx/3xx ", el("span", { className: "seg warning" }), " 4xx ", el("span", { className: "seg error" }), " 5xx");
    return [
      el("div", { className: "stats" },
        el("div", { className: "stat" }, el("small", {}, "Requests, 24 h"), el("strong", {}, total.toLocaleString())),
        el("div", { className: "stat" }, el("small", {}, "Server errors, 24 h"), el("strong", { className: r.hours.some((h) => h.server_error) ? "error" : "" }, String(r.hours.reduce((a, h) => a + h.server_error, 0)))),
        el("div", { className: "stat" }, el("small", {}, "Sign-ups, 14 d"), el("strong", {}, String(r.days.reduce((a, d) => a + d.sign_ups, 0)))),
        el("div", { className: "stat" }, el("small", {}, "Sign-ins, 14 d"), el("strong", {}, String(r.days.reduce((a, d) => a + d.sign_ins, 0))))),
      el("h2", {}, "Requests per hour"),
      ...(total ? [bars(r.hours.map((h) => ({ label: hourLabel(h.hour), title: `${hourLabel(h.hour)}:00 — ${h.ok} ok, ${h.client_error} client errors, ${h.server_error} server errors`,
        values: [{ value: h.ok, kind: "ok" }, { value: h.client_error, kind: "warning" }, { value: h.server_error, kind: "error" }] }))), legend] : [emptyState(icon("chart"), "No requests in the last 24 hours", "Core's access log is the source; it appears once core writes to its log volume.")]),
      el("h2", {}, "By service"),
      grid(["service", "requests", "5xx", "p50", "p95"], r.services.map((s) => el("tr", {}, el("td", {}, el("strong", {}, s.service)), el("td", {}, s.requests.toLocaleString()), el("td", {}, s.errors ? el("span", { className: "error" }, String(s.errors)) : "0"),
        el("td", {}, s.p50_ms === null ? "" : `${s.p50_ms.toFixed(1)} ms`), el("td", {}, s.p95_ms === null ? "" : `${s.p95_ms.toFixed(1)} ms`))), "No requests yet.", "chart"),
      el("h2", {}, "Sign-ups and sign-ins per day"),
      bars(r.days.map((d) => ({ label: d.day.slice(5), title: `${d.day}: ${d.sign_ups} sign-ups, ${d.sign_ins} sign-ins`, values: [{ value: d.sign_ups, kind: "ok" }, { value: d.sign_ins, kind: "accent" }] }))),
      el("p", { className: "hint legend" }, el("span", { className: "seg ok" }), " sign-ups ", el("span", { className: "seg accent" }), " sign-ins (new sessions)"),
      el("div", { className: "split" },
        el("div", {}, el("h2", {}, "Storage by bucket"), grid(["bucket", "files", "size"], r.buckets.map((b) => el("tr", {}, el("td", {}, b.bucket), el("td", {}, String(b.files)), el("td", {}, size(b.bytes)))), "No buckets.", "folder")),
        el("div", {}, el("h2", {}, "Largest tables"), grid(["table", "rows", "size"], r.tables.map((t) => el("tr", {}, el("td", {}, t.name), el("td", {}, (t.live_rows ?? 0).toLocaleString()), el("td", {}, size(t.bytes)))), "No tables.", "table"))),
    ];
  },

  async settings() {
    const s = await api<Settings>("/api/settings");
    const serviceKey = sessionStorage.getItem(KEY) ?? "";
    const masked = el("code", { className: "secretish" }, `${serviceKey.slice(0, 12)}…${serviceKey.slice(-6)}`);
    const reveal = button("Reveal", () => { masked.textContent = serviceKey; reveal.hidden = true; }, "small");
    const d = s.database;
    const conn = `postgres://${d.user}:<POSTGRES_PASSWORD>@${d.host}:${d.port}/${d.name}`;
    const health = (ok: boolean) => (ok ? badge("up", "ok") : badge("down or not enabled", "warning"));
    const archiver = s.archiver;
    const failing = typeof archiver.last_failed_time === "string" && (!archiver.last_archived_time || archiver.last_failed_time > String(archiver.last_archived_time));
    return [
      el("h2", {}, "General"),
      panel(kv("Project URL", s.public_url, s.public_url), kv("Postgres", el("span", {}, d.version)),
        kv("Services", el("span", {}, "core ", health(s.services.core!), " auth ", health(s.services.auth!), " graphql ", health(s.services.graphql!), " functions ", s.functions_mounted ? badge("directory mounted", "ok") : badge("not mounted")))),
      el("h2", {}, "API keys"),
      hint("The anon key is public: ship it in apps; RLS limits what it can do. The service_role key bypasses RLS: servers only, never a browser or a repository."),
      panel(kv("anon", s.anon_key, s.anon_key), el("div", { className: "kv" }, el("strong", {}, "service_role"), masked, reveal, copyButton(serviceKey)),
        kv("JWT", el("span", {}, `${s.jwt.alg ?? "?"} · key id `, el("code", {}, s.jwt.kid ?? "?"), ` · issuer ${s.jwt.issuer ?? "?"}`))),
      pre("# rotate every key (old tokens keep working during the overlap):\nuv run kilnbase rotate"),
      el("h2", {}, "Database"),
      panel(kv("Host", `${d.host}:${d.port}`), kv("Database", d.name), kv("User", d.user), kv("Connection string", conn, conn),
        hint("From the host, Postgres is reachable only inside the compose network: `docker compose exec db psql -U postgres`, or publish the port in an override file.")),
      details("Server settings", grid(["setting", "value"], d.settings.map((x) => el("tr", {}, el("td", {}, x.name), el("td", {}, el("code", {}, `${x.setting}${x.unit ? ` ${x.unit}` : ""}`)))), "")),
      el("h2", {}, "Backups"),
      panel(
        kv("WAL archiving", el("span", {}, archiver.archived_count ? badge(failing ? "failing" : "working", failing ? "error" : "ok") : badge("off (enable PITR)"),
          typeof archiver.last_archived_time === "string" ? ` last archive ${when(archiver.last_archived_time)}` : "",
          failing ? ` · last failure ${when(archiver.last_failed_time)}` : ""))),
      pre("uv run kilnbase backup                 # database + stored files as one archive\nuv run kilnbase restore <file>         # replace everything with a backup\nuv run kilnbase pitr enable            # continuous WAL archiving (pgBackRest)\nuv run kilnbase pitr backup            # run daily\nuv run kilnbase pitr list\nuv run kilnbase pitr restore --time \"2026-11-02 14:00:00+00\""),
      el("h2", {}, "Logs"),
      panel(...Object.entries(s.logs).map(([n, b]) => kv(n, el("span", {}, b === null ? "no file yet" : size(b)))), button("Open logs →", () => nav.show("logs"), "small")),
      el("h2", {}, "Upgrade"),
      pre("uv run kilnbase upgrade                # back up, pull the new version, roll back if it fails"),
    ];
  },
};


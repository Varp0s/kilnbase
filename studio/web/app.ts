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
interface User { id: string; email: string | null; created_at: string; is_anonymous: boolean }
interface ViewAsResult { role: string; claims: Row; denied: boolean; rows: Row[] }

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
    const load = () => api<User[]>(`/api/users?search=${encodeURIComponent(search.value)}`)
      .then((users) => result.replaceChildren(table(users as unknown as Row[], ["email", "id", "created_at", "is_anonymous"])))
      .catch((err: unknown) => fail(err, result));
    const form = el("form", {}, el("label", { htmlFor: "user-search" }, "Search"), search, el("button", { type: "submit" }, "Find"));
    form.addEventListener("submit", (e) => { e.preventDefault(); void load(); });
    void load();
    return [form, result];
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

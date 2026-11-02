// Shared by every page: DOM helpers, the API client, tables, icons, and the "run this SQL"
// confirmation. Rows written by end users are shown on a page that holds the service_role key, so
// everything is rendered with textContent / DOM APIs; innerHTML is never used.
import { confirmDialog, emptyState, h, toast } from "./ui";

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Row = Record<string, Json>;

export const KEY = "kilnbase-studio-key";
export const PAGE = 50;
export const el = h;

/** Set by main.ts: navigation and sign-out live there, every page needs them. */
export const nav = {
  show: (_name: string): Promise<void> => Promise.resolve(),
  signOut: (_message: string): void => {},
};

export class SignedOut extends Error {}

export function text(value: Json | undefined): string {
  if (value === null || value === undefined) return "null";
  return typeof value === "string" ? value : JSON.stringify(value);
}

export function when(value: Json | undefined, time = false): string {
  if (typeof value !== "string" && typeof value !== "number") return "";
  const d = new Date(typeof value === "number" ? value * 1000 : value);
  return Number.isNaN(d.getTime()) ? String(value) : time ? d.toLocaleTimeString() : d.toLocaleString();
}

export function size(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let n = bytes, i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : n} ${units[i]}`;
}

export function quoteIdent(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

export function quoteLiteral(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

const ICONS: Record<string, string[]> = {
  folder: ["M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"],
  file: ["M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z", "M14 3v5h5"],
  upload: ["M12 16V4", "M7 9l5-5 5 5", "M5 20h14"],
  download: ["M12 4v12", "M7 11l5 5 5-5", "M5 20h14"],
  refresh: ["M20 11a8 8 0 0 0-14.9-4M4 4v4h4", "M4 13a8 8 0 0 0 14.9 4M20 20v-4h-4"],
  copy: ["M9 9h11v11H9z", "M5 15V5a1 1 0 0 1 1-1h9"],
  table: ["M3 6a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z", "M3 10h18M9 10v10"],
  users: ["M9 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z", "M2 20v-1a5 5 0 0 1 5-5h4a5 5 0 0 1 5 5v1", "M16 3.5a4 4 0 0 1 0 8M22 20v-1a5 5 0 0 0-3.5-4.8"],
  inbox: ["M3 13l3-8h12l3 8v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z", "M3 13h5l1 3h6l1-3h5"],
  clock: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M12 7v5l3 2"],
  bolt: ["M13 2L4 14h7l-1 8 9-12h-7z"],
  alert: ["M12 3l10 18H2z", "M12 10v5M12 18h.01"],
  check: ["M5 12l5 5L20 7"],
  database: ["M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z", "M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"],
  code: ["M8 8l-4 4 4 4", "M16 8l4 4-4 4", "M14 4l-4 16"],
  radio: ["M12 12h.01", "M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7", "M5.6 5.6a9 9 0 0 0 0 12.8M18.4 5.6a9 9 0 0 1 0 12.8"],
  chart: ["M4 20h16", "M6 16v-5M11 16V7M16 16v-3M21 16V4"],
  shield: ["M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"],
  settings: ["M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z", "M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.8 1.2V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.8H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"],
};

export function icon(name: string): SVGSVGElement {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ICONS[name] ?? []) {
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    svg.append(path);
  }
  return svg;
}

/** Raw requests for file bodies; same key handling as api(). */
export async function request(path: string, init: RequestInit = {}): Promise<Response> {
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

export async function api<T>(path: string, body?: unknown): Promise<T> {
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

export function fail(err: unknown, target: HTMLElement): void {
  if (err instanceof SignedOut) return nav.signOut("The key was rejected.");
  target.replaceChildren(el("p", { className: "error", role: "alert" }, err instanceof Error ? err.message : String(err)));
}

export function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function table(rows: Row[], columns?: string[]): HTMLElement {
  if (rows.length === 0) return emptyState(icon("table"), "No rows");
  const cols = columns ?? Object.keys(rows[0] ?? {});
  const head = el("tr", {}, ...cols.map((c) => el("th", {}, c)));
  const body = rows.map((r) => el("tr", {}, ...cols.map((c) => el("td", {}, el("code", {}, text(r[c]))))));
  return el("div", { className: "scroll" }, el("table", {}, el("thead", {}, head), el("tbody", {}, ...body)));
}

/** A table built from prepared rows, or an empty state. */
export function grid(head: string[], rows: HTMLElement[], empty: string, ico = "table", detail = ""): HTMLElement {
  return rows.length
    ? el("div", { className: "scroll" }, el("table", {}, el("thead", {}, el("tr", {}, ...head.map((x) => el("th", {}, x)))), el("tbody", {}, ...rows)))
    : emptyState(icon(ico), empty, detail);
}

export function badge(label: string, kind: "ok" | "error" | "warning" | "" = ""): HTMLElement {
  return el("span", { className: `badge ${kind}` }, label);
}

export function button(label: string | (Node | string)[], onClick: () => unknown, className = ""): HTMLButtonElement {
  const b = el("button", { type: "button", className }, ...(typeof label === "string" ? [label] : label));
  b.addEventListener("click", () => void onClick());
  return b;
}

export function copyButton(value: string, label = "Copy"): HTMLButtonElement {
  return button(label, () => navigator.clipboard.writeText(value).then(() => toast("Copied to the clipboard")), "small");
}

/** Tabs that change `location.hash` to `#view/tab`; the page re-renders through nav.show. */
export function tabs(view: string, items: [string, string][], active: string): HTMLElement {
  const bar = el("div", { className: "tabs", role: "tablist" });
  for (const [id, label] of items) {
    const b = el("button", { type: "button", role: "tab" }, label);
    b.setAttribute("aria-selected", String(id === active));
    b.addEventListener("click", () => void nav.show(`${view}/${id}`));
    bar.append(b);
  }
  return bar;
}

export function details(summary: string, body: Node | string): HTMLElement {
  return el("details", {}, el("summary", {}, summary), typeof body === "string" ? el("pre", { className: "code" }, body) : body);
}

/** Opens the SQL editor with `sql` filled in; nothing runs until the admin presses Run. */
export function draftSql(sql: string): void {
  sessionStorage.setItem("kilnbase-studio-sql", sql);
  void nav.show("sql");
}

export interface SqlResult { columns: string[]; rows: Json[][]; truncated: boolean; status: string; committed: boolean }

/**
 * Shows the statement, runs it on confirmation (as the database superuser, like the SQL editor)
 * and reports the outcome. Every schema change in Studio goes through here, so the admin always
 * sees the exact SQL first.
 */
export async function runSql(
  sql: string,
  { title, confirmLabel = "Run", danger = false, success = "" }: { title: string; confirmLabel?: string; danger?: boolean; success?: string },
): Promise<boolean> {
  const body = el("div", {},
    el("pre", { className: "code" }, sql),
    el("p", { className: "hint" }, "Runs as the database superuser and is not recorded in db/migrations."));
  if (!(await confirmDialog(title, body, { confirmLabel, danger }))) return false;
  try {
    const r = await api<SqlResult>("/api/sql", { query: sql, rollback: false });
    toast(success || r.status);
    return true;
  } catch (err) {
    toast(message(err), "error");
    return false;
  }
}

export function downloadText(name: string, content: string, type = "text/plain"): void {
  const a = el("a", { href: URL.createObjectURL(new Blob([content], { type })), download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
}

export function toCsv(columns: string[], rows: Json[][]): string {
  const cell = (v: Json | undefined) => {
    const s = v === null || v === undefined ? "" : typeof v === "string" ? v : JSON.stringify(v);
    return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
  };
  return [columns, ...rows].map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

/** RFC 4180 parsing: quoted fields, doubled quotes, CR LF or LF. */
export function parseCsv(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], field = "", quoted = false;
  for (let i = 0; i < input.length; i++) {
    const c = input[i]!;
    if (quoted) {
      if (c === '"' && input[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && input[i + 1] === "\n") i++;
      row.push(field); rows.push(row); row = []; field = "";
    } else field += c;
  }
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.length > 1 || (r[0] ?? "") !== "");
}

// Shapes shared by several pages.
export interface Policy { name: string; command: string; roles: string[]; using: string | null; check: string | null }
export interface TableInfo { name: string; rls: boolean; policies: Policy[] }
export interface Column { name: string; type: string; nullable: boolean; default: string | null; primary_key: boolean; read_only: boolean }
export interface RowsPage { columns: Column[]; key: string[]; rows: Row[]; total: number }
export interface User {
  id: string; email: string | null; phone: string | null; created_at: string; is_anonymous: boolean;
  email_confirmed_at: string | null; last_sign_in_at: string | null; active_sessions: number;
}
export interface Connect { url: string; anon_key: string }

/** A labelled field that stacks its control under the label. */
export function field(label: string, control: HTMLElement, hint = ""): HTMLElement {
  return el("label", { className: "field" }, el("span", {}, label, hint ? el("small", {}, ` ${hint}`) : ""), control);
}

export function option(value: string, label = value): HTMLOptionElement {
  return el("option", { value }, label);
}

export function pre(code: string): HTMLElement {
  return el("pre", { className: "code" }, code);
}

export function hint(...parts: (string | Node)[]): HTMLElement {
  return el("p", { className: "hint" }, ...parts);
}

export function panel(...children: (string | Node)[]): HTMLElement {
  return el("div", { className: "panel" }, ...children);
}

/** Error text shown next to a form, or as a toast when there is no place for it. */
export function report(err: unknown, target?: HTMLElement): void {
  if (target) fail(err, target);
  else if (err instanceof SignedOut) nav.signOut("The key was rejected.");
  else toast(message(err), "error");
}

export { toast };

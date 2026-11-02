// Auth pages: one user, every active session, the auth service's settings.
import { confirmDialog, toast } from "./ui";
import { api, badge, button, copyButton, el, fail, grid, hint, nav, panel, pre, when } from "./lib";

interface UserDetail {
  id: string; email: string | null; phone: string | null; created_at: string; updated_at: string; is_anonymous: boolean;
  email_confirmed_at: string | null; last_sign_in_at: string | null; has_password: boolean;
  identities: { provider: string; provider_user_id: string; email: string | null; created_at: string }[];
  factors: { id: string; verified: boolean; created_at: string }[];
  sessions: { id: string; created_at: string; revoked_at: string | null; aal: string; recovery: boolean; refreshed_at: string | null }[];
}
interface Session { id: string; user_id: string; email: string | null; phone: string | null; created_at: string; aal: string; recovery: boolean; refreshed_at: string | null }
interface AuthSettings {
  providers: string[]; saml_providers: string[]; email: boolean; phone: boolean; anonymous_sign_in: boolean; mfa_required: boolean;
  redirect_urls: string[]; mails_per_ip_hour: number; min_password_length: number; access_token_lifetime: number;
}

function kv(label: string, value: string | Node): HTMLElement {
  return el("div", { className: "kv" }, el("strong", {}, label), typeof value === "string" ? el("span", {}, value) : value);
}

export const authViews: Record<string, (sub: string) => Promise<Node[]>> = {
  async user(sub) {
    if (!sub) return [hint("Open a user from the Users page.")];
    const u = await api<UserDetail>(`/api/users/${encodeURIComponent(sub)}`);
    const msg = el("p", { className: "hint" });
    const reload = () => nav.show(`user/${u.id}`);
    const who = u.email ?? u.phone ?? "Anonymous user";
    const act = async (action: string, title: string, question: string, danger = true) => {
      if (!(await confirmDialog(title, question, { confirmLabel: title, danger }))) return;
      api(`/api/users/${u.id}/${action}`, {}).then(() => { toast("Done"); if (action === "delete") void nav.show("users"); else void reload(); }).catch((err: unknown) => fail(err, msg));
    };
    const send = (kind: string, label: string) => api<{ sent?: boolean }>(`/api/users/${u.id}/send/${kind}`, {})
      .then(() => toast(`${label} sent to ${u.email}`)).catch((err: unknown) => fail(err, msg));
    const actions = el("div", { className: "toolbar" },
      u.email && !u.email_confirmed_at ? button("Confirm email", () => act("confirm-email", "Confirm email", `Mark ${u.email} as confirmed?`, false)) : "",
      u.email ? button("Send password reset", () => send("recover", "Password reset mail")) : "",
      u.email ? button("Send magic link", () => send("magic-link", "Magic link")) : "",
      u.sessions.some((s) => !s.revoked_at) ? button("Sign out everywhere", () => act("sign-out", "Sign out everywhere", "Refresh tokens stop working now; access tokens already issued stay valid for up to an hour.")) : "",
      button("Delete user", () => act("delete", "Delete user", `Delete ${who} and everything linked to the account? This cannot be undone.`), "danger"));
    const sessions = u.sessions.map((s) => el("tr", {},
      el("td", { title: s.id }, el("code", {}, `${s.id.slice(0, 8)}…`)), el("td", {}, when(s.created_at)),
      el("td", {}, s.refreshed_at ? when(s.refreshed_at) : "never"),
      el("td", {}, badge(s.aal, s.aal === "aal2" ? "ok" : ""), s.recovery ? badge("recovery", "warning") : ""),
      el("td", {}, s.revoked_at ? badge(`revoked ${when(s.revoked_at)}`) : badge("active", "ok")),
      el("td", { className: "actions" }, s.revoked_at ? "" : button("Revoke", () => api(`/api/sessions/${s.id}/revoke`, {}).then(() => { toast("Session revoked"); void reload(); }).catch((err: unknown) => fail(err, msg)), "danger"))));
    const factors = u.factors.map((f) => el("tr", {},
      el("td", { title: f.id }, el("code", {}, `${f.id.slice(0, 8)}…`)), el("td", {}, "TOTP"), el("td", {}, f.verified ? badge("verified", "ok") : badge("pending")), el("td", {}, when(f.created_at)),
      el("td", { className: "actions" }, button("Remove", async () => {
        if (!(await confirmDialog("Remove this factor?", "The user signs in with their password alone until they enrol again. Use it when an authenticator was lost.", { confirmLabel: "Remove factor", danger: true }))) return;
        api(`/api/users/${u.id}/factors/${f.id}/delete`, {}).then(() => { toast("Factor removed"); void reload(); }).catch((err: unknown) => fail(err, msg));
      }, "danger"))));
    const identities = u.identities.map((i) => el("tr", {}, el("td", {}, badge(i.provider)), el("td", {}, el("code", {}, i.provider_user_id)), el("td", {}, i.email ?? ""), el("td", {}, when(i.created_at))));
    return [
      el("div", { className: "toolbar" }, button("← Users", () => nav.show("users"), "small"), button("View as this user →", () => nav.show("viewas"), "small")),
      panel(
        kv("ID", el("span", {}, el("code", {}, u.id), " ", copyButton(u.id))),
        kv("Email", u.email ? el("span", {}, u.email, " ", u.email_confirmed_at ? badge("confirmed", "ok") : badge("unconfirmed", "warning")) : "—"),
        kv("Phone", u.phone ?? "—"),
        kv("Sign-in", [u.has_password ? "password" : "", ...u.identities.map((i) => i.provider), u.is_anonymous ? "anonymous" : ""].filter(Boolean).join(", ") || "link or code only"),
        kv("MFA", u.factors.some((f) => f.verified) ? "enrolled" : "not enrolled"),
        kv("Created", when(u.created_at)), kv("Last sign-in", u.last_sign_in_at ? when(u.last_sign_in_at) : "never")),
      actions, msg,
      el("h2", {}, "Sessions"), grid(["session", "started", "last refreshed", "level", "", ""], sessions, "No sessions yet.", "users"),
      el("h2", {}, "Identities"), grid(["provider", "provider user id", "email", "linked"], identities, "No OAuth or SAML identity linked.", "users"),
      el("h2", {}, "Multi-factor"), grid(["factor", "type", "", "enrolled", ""], factors, "No authenticator enrolled.", "shield"),
    ];
  },

  async sessions() {
    const result = el("div");
    const search = el("input", { type: "search", id: "session-search", placeholder: "email or phone contains…" });
    const msg = el("p", { className: "hint" });
    const load = () => api<Session[]>(`/api/sessions?search=${encodeURIComponent(search.value)}`).then((list) => {
      result.replaceChildren(grid(["user", "started", "last refreshed", "level", ""], list.map((s) => el("tr", {},
        el("td", {}, button(s.email ?? s.phone ?? s.user_id, () => nav.show(`user/${s.user_id}`), "link")),
        el("td", {}, when(s.created_at)), el("td", {}, s.refreshed_at ? when(s.refreshed_at) : "never"),
        el("td", {}, badge(s.aal, s.aal === "aal2" ? "ok" : ""), s.recovery ? badge("recovery", "warning") : ""),
        el("td", { className: "actions" }, button("Revoke", () => api(`/api/sessions/${s.id}/revoke`, {}).then(() => { toast("Session revoked"); void load(); }).catch((err: unknown) => fail(err, msg)), "danger")))),
        "No active sessions.", "users"), list.length === 100 ? hint("The newest 100 are shown; search to narrow down.") : "");
    }).catch((err: unknown) => fail(err, result));
    const form = el("form", {}, el("label", { htmlFor: "session-search" }, "Search"), search, el("button", { type: "submit" }, "Find"));
    form.addEventListener("submit", (e) => { e.preventDefault(); void load(); });
    void load();
    return [hint("A session lives as long as its refresh token is used. Revoking one stops its refresh tokens now; its access token stays valid for up to an hour."), form, msg, result];
  },

  async authsettings() {
    const s = await api<AuthSettings>("/api/auth/settings");
    const on = (v: boolean) => (v ? badge("on", "ok") : badge("off"));
    const env = (name: string) => el("code", {}, name);
    return [
      hint("Auth is configured through .env; this page shows what the running auth service uses. Change a value there and run `docker compose up -d auth`."),
      el("h2", {}, "Sign-in methods"),
      panel(
        kv("Email + password", el("span", {}, badge("on", "ok"), " minimum password length ", String(s.min_password_length))),
        kv("Email links & codes", el("span", {}, on(s.email), " ", env("KILNBASE_SMTP_URL"), s.email ? "" : " (not set: no confirmation, recovery or magic-link mails)")),
        kv("Phone (SMS codes)", el("span", {}, on(s.phone), " ", env("KILNBASE_SMS_URL"))),
        kv("Anonymous sign-in", el("span", {}, on(s.anonymous_sign_in), " ", env("KILNBASE_AUTH_ANONYMOUS"))),
        kv("MFA required", el("span", {}, on(s.mfa_required), " ", env("KILNBASE_AUTH_MFA_REQUIRED"))),
        kv("OAuth providers", s.providers.length ? el("span", {}, ...s.providers.map((p) => badge(p, "ok"))) : el("span", {}, "none ", env("KILNBASE_OAUTH_<PROVIDER>_CLIENT_ID"))),
        kv("SAML providers", s.saml_providers.length ? el("span", {}, ...s.saml_providers.map((p) => badge(p, "ok"))) : el("span", {}, "none ", env("KILNBASE_SAML_<NAME>_METADATA_URL")))),
      el("h2", {}, "URLs"),
      panel(
        kv("Allowed redirect URLs", s.redirect_urls.length ? el("span", {}, ...s.redirect_urls.map((u) => el("code", { className: "chip" }, u))) : el("span", {}, "none beyond the public URL ", env("KILNBASE_AUTH_REDIRECT_URLS")))),
      el("h2", {}, "Limits"),
      panel(
        kv("Mails per IP per hour", el("span", {}, String(s.mails_per_ip_hour), " ", env("KILNBASE_AUTH_MAILS_PER_IP_HOUR"))),
        kv("Access token lifetime", `${s.access_token_lifetime / 60} minutes`)),
      el("h2", {}, "Example"),
      pre("# .env\nKILNBASE_SMTP_URL=smtps://user:pass@smtp.example.com:465\nKILNBASE_SMTP_FROM=\"My App <no-reply@example.com>\"\nKILNBASE_AUTH_REDIRECT_URLS=https://app.example.com/auth/callback\nKILNBASE_OAUTH_GITHUB_CLIENT_ID=…\nKILNBASE_OAUTH_GITHUB_CLIENT_SECRET=…"),
    ];
  },
};

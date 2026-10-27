// Shared UI pieces: confirm dialog, toasts, loading skeletons, empty states, theme and font.
// Everything is built with DOM APIs; this page holds the service_role key, so no innerHTML.
import interLatin from "@fontsource-variable/inter/files/inter-latin-wght-normal.woff2?url";
import interLatinExt from "@fontsource-variable/inter/files/inter-latin-ext-wght-normal.woff2?url";

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

/** Inter, served by Studio itself (the CSP allows no other origin); system fonts until it loads. */
export function loadFont(): void {
  const faces = [
    new FontFace("Inter Variable", `url(${interLatin}) format("woff2")`, {
      weight: "100 900", display: "swap",
      unicodeRange: "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+20AC,U+2122,U+2212,U+FEFF,U+FFFD",
    }),
    new FontFace("Inter Variable", `url(${interLatinExt}) format("woff2")`, {
      weight: "100 900", display: "swap",
      unicodeRange: "U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+1E00-1E9F,U+20A0-20AB,U+20AD-20C0,U+2C60-2C7F,U+A720-A7FF",
    }),
  ];
  for (const face of faces) document.fonts.add(face);
}

/** A modal yes/no question. Resolves false on Cancel, Escape or a click outside. */
export function confirmDialog(
  title: string,
  body: string,
  { confirmLabel = "Confirm", danger = false }: { confirmLabel?: string; danger?: boolean } = {},
): Promise<boolean> {
  return new Promise((resolve) => {
    const cancel = h("button", { type: "button" }, "Cancel");
    const ok = h("button", { type: "button", className: danger ? "solid-danger" : "solid" }, confirmLabel);
    const dialog = h("dialog", { className: "dialog" },
      h("h2", {}, title), h("p", {}, body), h("div", { className: "dialog-actions" }, cancel, ok));
    const close = (answer: boolean) => { dialog.close(); dialog.remove(); resolve(answer); };
    cancel.addEventListener("click", () => close(false));
    ok.addEventListener("click", () => close(true));
    dialog.addEventListener("cancel", (e) => { e.preventDefault(); close(false); });
    dialog.addEventListener("click", (e) => { if (e.target === dialog) close(false); });
    document.body.append(dialog);
    dialog.showModal();
    (danger ? cancel : ok).focus();
  });
}

/** A short message in the corner; errors stay until dismissed. */
export function toast(message: string, kind: "ok" | "error" = "ok"): void {
  let stack = document.getElementById("toasts");
  if (!stack) {
    stack = h("div", { id: "toasts", className: "toasts" });
    stack.setAttribute("aria-live", "polite");
    document.body.append(stack);
  }
  const close = h("button", { type: "button", className: "toast-close", title: "Dismiss" }, "×");
  const item = h("div", { className: `toast ${kind}`, role: kind === "error" ? "alert" : "status" }, h("span", {}, message), close);
  close.addEventListener("click", () => item.remove());
  stack.append(item);
  if (kind === "ok") setTimeout(() => item.remove(), 3500);
}

/** Grey placeholder lines while a page loads, shaped like the table that will replace them. */
export function skeleton(lines = 6): HTMLElement {
  const box = h("div", { className: "skeleton" });
  box.setAttribute("aria-label", "Loading");
  for (let i = 0; i < lines; i++) box.append(h("div", { className: "skeleton-line" }));
  return box;
}

export function emptyState(icon: Node, title: string, detail = ""): HTMLElement {
  return h("div", { className: "empty" }, icon, h("strong", {}, title), detail ? h("p", { className: "hint" }, detail) : "");
}

const THEMES = ["system", "light", "dark"] as const;
type Theme = (typeof THEMES)[number];

function savedTheme(): Theme {
  try {
    const value = localStorage.getItem("kilnbase-studio-theme");
    return THEMES.includes(value as Theme) ? (value as Theme) : "system";
  } catch {
    return "system";
  }
}

/** system → light → dark; remembered in this browser only. */
export function themeButton(): HTMLButtonElement {
  const button = h("button", { type: "button", className: "theme" });
  const apply = (theme: Theme) => {
    if (theme === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
    button.textContent = `Theme: ${theme}`;
  };
  let current = savedTheme();
  apply(current);
  button.addEventListener("click", () => {
    current = THEMES[(THEMES.indexOf(current) + 1) % THEMES.length]!;
    try { localStorage.setItem("kilnbase-studio-theme", current); } catch { /* private window: not remembered */ }
    apply(current);
  });
  return button;
}

const API_BASE = import.meta.env.VITE_API_BASE || "";

export type SessionRole = "admin" | "user" | null;

export interface SessionInfo {
  token: string;
  username: string | null;
  role: SessionRole;
}

type ApiOptions = RequestInit & {
  body?: BodyInit | null;
};

function formatDetail(detail: unknown) {
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === "string") {
          return item;
        }
        if (item && typeof item === "object" && "msg" in item) {
          const typed = item as { msg?: string; loc?: unknown };
          const path = Array.isArray(typed.loc) ? typed.loc.slice(1).join(".") : "";
          return path ? `${path}: ${typed.msg}` : typed.msg || "Request failed";
        }
        return JSON.stringify(item);
      })
      .join(" | ");
  }
  if (detail && typeof detail === "object" && "msg" in detail) {
    const typed = detail as { msg?: string };
    return typed.msg || "Request failed";
  }
  return (detail as string) || "Request failed";
}

export function getToken() {
  return localStorage.getItem("scanner_token") || "";
}

export function setSession(token: string, username: string, role: string) {
  localStorage.setItem("scanner_token", token);
  localStorage.setItem("scanner_username", username);
  localStorage.setItem("scanner_role", role);
}

export function clearSession() {
  localStorage.removeItem("scanner_token");
  localStorage.removeItem("scanner_username");
  localStorage.removeItem("scanner_role");
}

export function getSession(): SessionInfo {
  return {
    token: getToken(),
    username: localStorage.getItem("scanner_username"),
    role: (localStorage.getItem("scanner_role") as SessionRole) || null,
  };
}

export async function api<T = unknown>(path: string, options: ApiOptions = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  const token = getToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (!(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(formatDetail(payload.detail));
  }
  const type = response.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    return response.json() as Promise<T>;
  }
  return response.blob() as Promise<T>;
}

export async function downloadReport(path: string, filename: string) {
  const headers = new Headers();
  const token = getToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const response = await fetch(`${API_BASE}${path}`, { method: "GET", headers });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: "Download failed" }));
    throw new Error(formatDetail(payload.detail));
  }
  const blob = await response.blob();
  const objectUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.click();
  window.URL.revokeObjectURL(objectUrl);
}

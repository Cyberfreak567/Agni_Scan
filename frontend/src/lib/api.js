const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

function formatDetail(detail) {
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === "string") {
          return item;
        }
        if (item?.msg) {
          const path = Array.isArray(item.loc) ? item.loc.slice(1).join(".") : "";
          return path ? `${path}: ${item.msg}` : item.msg;
        }
        return JSON.stringify(item);
      })
      .join(" | ");
  }
  if (detail && typeof detail === "object") {
    return detail.msg || JSON.stringify(detail);
  }
  return detail || "Request failed";
}

export function getToken() {
  return localStorage.getItem("scanner_token") || "";
}

export function setSession(token, username, role) {
  localStorage.setItem("scanner_token", token);
  localStorage.setItem("scanner_username", username);
  localStorage.setItem("scanner_role", role);
}

export function clearSession() {
  localStorage.removeItem("scanner_token");
  localStorage.removeItem("scanner_username");
  localStorage.removeItem("scanner_role");
}

export function getSession() {
  return {
    token: getToken(),
    username: localStorage.getItem("scanner_username"),
    role: localStorage.getItem("scanner_role"),
  };
}

export async function api(path, options = {}) {
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
    return response.json();
  }
  return response.blob();
}

export async function downloadReport(path, filename) {
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

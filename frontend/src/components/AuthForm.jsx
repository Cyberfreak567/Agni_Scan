import { useState } from "react";
import { api, setSession } from "../lib/api";
import { FlameMark } from "./FlameMark";

export function AuthForm({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ username: "", password: "", role: "user" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const payload =
        mode === "login"
          ? { username: form.username, password: form.password }
          : { username: form.username, password: form.password, role: form.role };
      const data = await api(`/api/auth/${mode}`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setSession(data.token, data.username, data.role);
      onAuthenticated();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-panel">
        <div className="brand-lockup">
          <FlameMark />
          <div>
            <p className="eyebrow">Agniscan // Adversarial Validation Suite</p>
            <h1>Agniscan</h1>
            <p className="lede">
              Launch code and live-target assessments with a cinematic command-center interface built
              around Semgrep, Bandit, Nuclei, Nmap, Nikto, and OWASP-focused web checks.
            </p>
          </div>
        </div>
        <div className="auth-stage" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <form onSubmit={submit} className="auth-form">
          <label>
            Username
            <input
              value={form.username}
              onChange={(event) => setForm({ ...form, username: event.target.value })}
              placeholder="analyst_admin"
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={form.password}
              onChange={(event) => setForm({ ...form, password: event.target.value })}
              placeholder="Minimum 8 characters"
            />
          </label>
          {mode === "register" && (
            <label>
              Role
              <select value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}>
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
            </label>
          )}
          {error && <div className="error-banner">{error}</div>}
          <button disabled={loading}>{loading ? "Working..." : mode === "login" ? "Login" : "Register"}</button>
        </form>
        <div className="auth-switch">
          <span>{mode === "login" ? "Need an account?" : "Already registered?"}</span>
          <button type="button" className="ghost-button" onClick={() => setMode(mode === "login" ? "register" : "login")}>
            {mode === "login" ? "Register" : "Login"}
          </button>
        </div>
      </div>
    </div>
  );
}

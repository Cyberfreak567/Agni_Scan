import { useState } from "react";
import { motion } from "framer-motion";
import { api, setSession } from "../lib/api";
import { FlameMark } from "./FlameMark";

const shellTransition = { duration: 0.65, ease: [0.22, 1, 0.36, 1] };
const staggerParent = {
  hidden: {},
  show: {
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.08,
    },
  },
};
const riseIn = {
  hidden: { opacity: 0, y: 24 },
  show: { opacity: 1, y: 0, transition: shellTransition },
};

interface AuthFormProps {
  onAuthenticated: () => void;
}

type AuthMode = "login" | "register";

interface AuthState {
  username: string;
  password: string;
  role: "user" | "admin";
}

export function AuthForm({ onAuthenticated }: AuthFormProps) {
  const [mode, setMode] = useState<AuthMode>("login");
  const [form, setForm] = useState<AuthState>({ username: "", password: "", role: "user" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const payload =
        mode === "login"
          ? { username: form.username, password: form.password }
          : { username: form.username, password: form.password, role: form.role };
      const data = await api<{ token: string; username: string; role: string }>(`/api/auth/${mode}`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setSession(data.token, data.username, data.role);
      onAuthenticated();
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Unable to authenticate right now.");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-shell">
      <motion.div
        className="glass-panel auth-panel"
        initial={{ opacity: 0, y: 28, rotateX: 8 }}
        animate={{ opacity: 1, y: 0, rotateX: 0 }}
        transition={shellTransition}
      >
        <motion.div className="brand-lockup" variants={staggerParent} initial="hidden" animate="show">
          <FlameMark />
          <motion.div variants={riseIn}>
            <p className="eyebrow">Agniscan // Adversarial Validation Suite</p>
            <h1>Agniscan</h1>
            <p className="lede">
              Launch code and live-target assessments with a cinematic command-center interface built
              around Semgrep, Bandit, Nuclei, Nmap, Nikto, and OWASP-focused web checks.
            </p>
          </motion.div>
        </motion.div>
        <div className="auth-stage" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <motion.form
          onSubmit={submit}
          className="auth-form space-y-4"
          variants={staggerParent}
          initial="hidden"
          animate="show"
        >
          <motion.label variants={riseIn}>
            Username
            <input
              className="input-field"
              value={form.username}
              onChange={(event) => setForm({ ...form, username: event.target.value })}
              placeholder="analyst_admin"
            />
          </motion.label>
          <motion.label variants={riseIn}>
            Password
            <input
              type="password"
              className="input-field"
              value={form.password}
              onChange={(event) => setForm({ ...form, password: event.target.value })}
              placeholder="Minimum 8 characters"
            />
          </motion.label>
          {mode === "register" && (
            <motion.label variants={riseIn}>
              Role
              <select
                className="input-field"
                value={form.role}
                onChange={(event) => setForm({ ...form, role: event.target.value as AuthState["role"] })}
              >
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
            </motion.label>
          )}
          {error && (
            <motion.div variants={riseIn} className="rounded-2xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
              {error}
            </motion.div>
          )}
          <motion.button variants={riseIn} className="btn-primary w-full" disabled={loading}>
            {loading ? "Working..." : mode === "login" ? "Login" : "Register"}
          </motion.button>
        </motion.form>
        <motion.div
          className="auth-switch"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.28 }}
        >
          <span>{mode === "login" ? "Need an account?" : "Already registered?"}</span>
          <button type="button" className="btn-ghost" onClick={() => setMode(mode === "login" ? "register" : "login")}>
            {mode === "login" ? "Register" : "Login"}
          </button>
        </motion.div>
      </motion.div>
    </div>
  );
}

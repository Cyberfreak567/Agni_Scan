import { useState } from "react";
import { motion } from "framer-motion";
import { api } from "../lib/api";

function normalizeUrlInput(value: string) {
  return value.trim().split(/\s+/)[0] || "";
}

const cardTransition = { duration: 0.55, ease: [0.22, 1, 0.36, 1] };

interface ScanFormsProps {
  onCreated: () => void;
}

export function ScanForms({ onCreated }: ScanFormsProps) {
  const [repoUrl, setRepoUrl] = useState("");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [targetUrl, setTargetUrl] = useState("");
  const [dastMode, setDastMode] = useState<"full" | "quick">("full");
  const [message, setMessage] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submitSast(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    setSubmitting(true);
    try {
      const formData = new FormData();
      if (repoUrl) {
        formData.append("repo_url", normalizeUrlInput(repoUrl));
      }
      if (zipFile) {
        formData.append("file", zipFile);
      }
      await api("/api/scans/sast", { method: "POST", body: formData });
      setRepoUrl("");
      setZipFile(null);
      setMessage("SAST scan queued successfully.");
      onCreated();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Unable to start SAST scan.");
    } finally {
      setSubmitting(false);
    }
  }

  async function submitDast(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    setSubmitting(true);
    try {
      await api("/api/scans/dast", {
        method: "POST",
        body: JSON.stringify({ target_url: normalizeUrlInput(targetUrl), mode: dastMode }),
      });
      setTargetUrl("");
      setMessage(`DAST ${dastMode} scan queued successfully.`);
      onCreated();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Unable to start DAST scan.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <motion.form
        className="glass-panel p-6"
        onSubmit={submitSast}
        initial={{ opacity: 0, y: 28, rotateX: 8 }}
        animate={{ opacity: 1, y: 0, rotateX: 0 }}
        transition={cardTransition}
      >
        <h2 className="text-xl font-semibold text-white">SAST</h2>
        <p className="mt-2 text-sm text-muted">Submit a GitHub repository URL or upload a ZIP archive for Semgrep and Bandit.</p>
        <label className="mt-4 block text-sm text-muted">
          <span className="input-label">GitHub repo URL</span>
          <input
            type="url"
            autoComplete="off"
            spellCheck="false"
            className="input-field mt-2"
            value={repoUrl}
            onChange={(event) => setRepoUrl(event.target.value)}
            placeholder="https://github.com/org/repo"
          />
        </label>
        <label className="mt-4 block text-sm text-muted">
          <span className="input-label">ZIP upload</span>
          <input
            type="file"
            accept=".zip"
            className="mt-2 block w-full text-xs text-muted file:mr-4 file:rounded-full file:border-0 file:bg-white/10 file:px-4 file:py-2 file:text-xs file:font-semibold file:text-ink/80"
            onChange={(event) => setZipFile(event.target.files?.[0] || null)}
          />
        </label>
        <button className="btn-primary mt-5" disabled={submitting}>
          {submitting ? "Launching..." : "Launch SAST Scan"}
        </button>
      </motion.form>
      <motion.form
        className="glass-panel p-6"
        onSubmit={submitDast}
        initial={{ opacity: 0, y: 28, rotateX: 8 }}
        animate={{ opacity: 1, y: 0, rotateX: 0 }}
        transition={{ ...cardTransition, delay: 0.08 }}
      >
        <h2 className="text-xl font-semibold text-white">DAST</h2>
        <p className="mt-2 text-sm text-muted">
          Probe a live target with OWASP-focused web checks, Nuclei, Nmap, and optional Nikto. The target must be HTTP or HTTPS.
        </p>
        <label className="mt-4 block text-sm text-muted">
          <span className="input-label">Scan mode</span>
          <select
            className="input-field mt-2"
            value={dastMode}
            onChange={(event) => setDastMode(event.target.value as "full" | "quick")}
          >
            <option value="full">Full scan</option>
            <option value="quick">Quick scan</option>
          </select>
        </label>
        <label className="mt-4 block text-sm text-muted">
          <span className="input-label">Target URL</span>
          <input
            type="url"
            autoComplete="off"
            spellCheck="false"
            className="input-field mt-2"
            value={targetUrl}
            onChange={(event) => setTargetUrl(event.target.value)}
            placeholder="https://example.com"
          />
        </label>
        <button className="btn-primary mt-5" disabled={submitting}>
          {submitting ? "Launching..." : "Launch DAST Scan"}
        </button>
      </motion.form>
      {message && (
        <motion.div
          className="glass-panel px-4 py-3 text-sm text-muted"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={cardTransition}
        >
          {message}
        </motion.div>
      )}
    </div>
  );
}

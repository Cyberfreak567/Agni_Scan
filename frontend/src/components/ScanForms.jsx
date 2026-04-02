import { useState } from "react";
import { motion } from "framer-motion";
import { api } from "../lib/api";

function normalizeUrlInput(value) {
  return value.trim().split(/\s+/)[0] || "";
}

const cardTransition = { duration: 0.55, ease: [0.22, 1, 0.36, 1] };

export function ScanForms({ onCreated }) {
  const [repoUrl, setRepoUrl] = useState("");
  const [zipFile, setZipFile] = useState(null);
  const [targetUrl, setTargetUrl] = useState("");
  const [dastMode, setDastMode] = useState("full");
  const [message, setMessage] = useState("");

  async function submitSast(event) {
    event.preventDefault();
    setMessage("");
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
      setMessage(err.message);
    }
  }

  async function submitDast(event) {
    event.preventDefault();
    setMessage("");
    try {
      await api("/api/scans/dast", {
        method: "POST",
        body: JSON.stringify({ target_url: normalizeUrlInput(targetUrl), mode: dastMode }),
      });
      setTargetUrl("");
      setMessage(`DAST ${dastMode} scan queued successfully.`);
      onCreated();
    } catch (err) {
      setMessage(err.message);
    }
  }

  return (
    <div className="form-grid">
      <motion.form
        className="panel mission-panel"
        onSubmit={submitSast}
        initial={{ opacity: 0, y: 28, rotateX: 8 }}
        animate={{ opacity: 1, y: 0, rotateX: 0 }}
        transition={cardTransition}
      >
        <h2>SAST</h2>
        <p className="section-copy">Submit a GitHub repository URL or upload a ZIP archive for Semgrep and Bandit.</p>
        <label>
          GitHub repo URL
          <input
            type="url"
            autoComplete="off"
            spellCheck="false"
            value={repoUrl}
            onChange={(event) => setRepoUrl(event.target.value)}
            placeholder="https://github.com/org/repo"
          />
        </label>
        <label>
          ZIP upload
          <input type="file" accept=".zip" onChange={(event) => setZipFile(event.target.files?.[0] || null)} />
        </label>
        <button>Launch SAST Scan</button>
      </motion.form>
      <motion.form
        className="panel mission-panel"
        onSubmit={submitDast}
        initial={{ opacity: 0, y: 28, rotateX: 8 }}
        animate={{ opacity: 1, y: 0, rotateX: 0 }}
        transition={{ ...cardTransition, delay: 0.08 }}
      >
        <h2>DAST</h2>
        <p className="section-copy">Probe a live target with OWASP-focused web checks, Nuclei, Nmap, and optional Nikto. The target must be HTTP or HTTPS.</p>
        <label>
          Scan mode
          <select value={dastMode} onChange={(event) => setDastMode(event.target.value)}>
            <option value="full">Full scan</option>
            <option value="quick">Quick scan</option>
          </select>
        </label>
        <label>
          Target URL
          <input
            type="url"
            autoComplete="off"
            spellCheck="false"
            value={targetUrl}
            onChange={(event) => setTargetUrl(event.target.value)}
            placeholder="https://example.com"
          />
        </label>
        <button>Launch DAST Scan</button>
      </motion.form>
      {message && (
        <motion.div
          className="status-banner"
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

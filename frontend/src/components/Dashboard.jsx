import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { api, clearSession, downloadReport, getSession } from "../lib/api";
import { ScanForms } from "./ScanForms";
import { FlameMark } from "./FlameMark";

const reveal = {
  hidden: { opacity: 0, y: 24 },
  show: { opacity: 1, y: 0, transition: { duration: 0.58, ease: [0.22, 1, 0.36, 1] } },
};

const stagger = {
  hidden: {},
  show: {
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.06,
    },
  },
};

function severityColor(severity) {
  return {
    critical: "pill critical",
    high: "pill high",
    medium: "pill medium",
    low: "pill low",
    info: "pill info",
  }[severity] || "pill";
}

function groupFindings(items = []) {
  return {
    vulnerabilities: items.filter((item) => item.finding_kind === "vulnerability"),
    observations: items.filter((item) => item.finding_kind !== "vulnerability"),
  };
}

function getSuggestedFixes(item) {
  const suggestions = [];
  const owasp = (item.owasp_category || "").toLowerCase();
  const tool = (item.tool || "").toLowerCase();

  if (owasp.includes("broken access")) {
    suggestions.push("Enforce authorization checks on the server for every sensitive action.");
    suggestions.push("Add unit tests for role-based permissions to prevent regressions.");
  }
  if (owasp.includes("cryptographic")) {
    suggestions.push("Force HTTPS and enable HSTS with a long max-age.");
    suggestions.push("Ensure cookies are marked Secure and HttpOnly.");
  }
  if (owasp.includes("injection")) {
    suggestions.push("Use parameterized queries or ORM-safe APIs to eliminate string concatenation.");
    suggestions.push("Add input validation and logging for unexpected payloads.");
  }
  if (owasp.includes("security misconfiguration")) {
    suggestions.push("Harden server headers (CSP, X-Frame-Options, X-Content-Type-Options).");
    suggestions.push("Disable directory listing and remove default debug endpoints.");
  }
  if (tool.includes("semgrep") || tool.includes("bandit")) {
    suggestions.push("Refactor the flagged code path and add a regression test.");
  }
  if (tool.includes("nuclei") || tool.includes("nikto")) {
    suggestions.push("Verify the finding manually and patch the vulnerable endpoint.");
  }
  if (tool.includes("nmap")) {
    suggestions.push("Close unused ports or restrict access with security groups/firewall rules.");
  }

  if (!suggestions.length) {
    suggestions.push("Validate the issue and implement the recommended mitigation.");
  }
  return suggestions.slice(0, 3);
}

export function Dashboard() {
  const session = getSession();
  const [summary, setSummary] = useState(null);
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [tools, setTools] = useState({});
  const [error, setError] = useState("");
  const [view, setView] = useState("overview");

  async function refresh() {
    try {
      const [scanData, toolData] = await Promise.all([api("/api/scans"), api("/api/scans/tools")]);
      setScans(scanData);
      setTools(toolData);
      if (scanData.length > 0) {
        const active = selectedScan ? scanData.find((item) => item.id === selectedScan.id) : scanData[0];
        setSelectedScan(active || scanData[0]);
      } else {
        setSelectedScan(null);
      }
      if (session.role === "admin") {
        const summaryData = await api("/api/scans/admin/summary");
        setSummary(summaryData);
      }
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }

  async function deleteScan(scanId) {
    const confirmed = window.confirm(`Delete scan #${scanId}? This will remove its findings and reports.`);
    if (!confirmed) {
      return;
    }
    try {
      await api(`/api/scans/${scanId}`, { method: "DELETE" });
      if (selectedScan?.id === scanId) {
        setSelectedScan(null);
      }
      await refresh();
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const syncView = () => {
      const hash = window.location.hash.replace("#/", "") || "overview";
      setView(hash);
    };
    syncView();
    window.addEventListener("hashchange", syncView);
    return () => window.removeEventListener("hashchange", syncView);
  }, []);

  const grouped = groupFindings(selectedScan?.vulnerabilities || []);

  const ViewPanel = () => {
    if (view === "scans") {
      return (
        <>
          <ScanForms onCreated={refresh} />
          {error && <div className="error-banner">{error}</div>}
          <div className="content-grid">
            <motion.section className="panel" initial={{ opacity: 0, x: -24 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.58 }}>
              <h2>All Scans</h2>
              <motion.div className="scan-list" initial="hidden" animate="show" variants={stagger}>
                {scans.map((scan) => (
                  <motion.div
                    key={scan.id}
                    className={`scan-row ${selectedScan?.id === scan.id ? "active" : ""}`}
                    variants={reveal}
                    whileHover={{ y: -6, rotateX: 3 }}
                    layout
                  >
                    <button type="button" className="scan-select" onClick={() => setSelectedScan(scan)}>
                      <div><strong>#{scan.id}</strong> {scan.scan_type.toUpperCase()} {scan.scan_mode ? `(${scan.scan_mode})` : ""}</div>
                      <div className="scan-target">{scan.target}</div>
                      <div className="scan-meta-line">
                        <span>{scan.status}</span>
                        <span>{scan.current_stage || "Queued"}</span>
                        <span>{scan.progress}%</span>
                      </div>
                    </button>
                    <button type="button" className="ghost-button delete-button" onClick={() => deleteScan(scan.id)}>Delete</button>
                  </motion.div>
                ))}
                {!scans.length && <p>No scans yet.</p>}
              </motion.div>
            </motion.section>
          </div>
        </>
      );
    }

    if (view === "findings") {
      return (
        <div className="content-grid">
          <motion.section className="panel detail-panel" initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.58 }}>
            <h2>Detailed Report</h2>
            {selectedScan ? (
              <>
                <div className="detail-meta">
                  <div><span>Target</span><strong>{selectedScan.target}</strong></div>
                  <div><span>Status</span><strong>{selectedScan.status}</strong></div>
                  <div><span>Mode</span><strong>{selectedScan.scan_mode || "-"}</strong></div>
                  <div><span>Stage</span><strong>{selectedScan.current_stage || "-"}</strong></div>
                </div>
                <div className="progress-track">
                  <motion.div
                    className="progress-bar"
                    initial={{ width: 0 }}
                    animate={{ width: `${selectedScan.progress}%` }}
                    transition={{ duration: 0.7, ease: "easeOut" }}
                  />
                </div>
                <div className="report-actions">
                  <button type="button" onClick={async () => {
                    try { await downloadReport(`/api/reports/${selectedScan.id}/html`, `scan_${selectedScan.id}.html`); } catch (err) { setError(err.message); }
                  }}>HTML</button>
                  <button type="button" onClick={async () => {
                    try { await downloadReport(`/api/reports/${selectedScan.id}/pdf`, `scan_${selectedScan.id}.pdf`); } catch (err) { setError(err.message); }
                  }}>PDF</button>
                  <button type="button" onClick={async () => {
                    try { await downloadReport(`/api/reports/${selectedScan.id}/json`, `scan_${selectedScan.id}.json`); } catch (err) { setError(err.message); }
                  }}>JSON</button>
                  <button type="button" className="ghost-button delete-button" onClick={() => deleteScan(selectedScan.id)}>Delete</button>
                </div>

                <div className="summary-grid compact">
                  <div className="panel inset metric-panel"><h3>Verified vulnerabilities</h3><p>{selectedScan.summary?.total_vulnerabilities ?? 0}</p></div>
                  <div className="panel inset metric-panel"><h3>Observations</h3><p>{selectedScan.summary?.total_observations ?? 0}</p></div>
                  <div className="panel inset metric-panel"><h3>High + Critical</h3><p>{(selectedScan.summary?.severity_distribution?.high ?? 0) + (selectedScan.summary?.severity_distribution?.critical ?? 0)}</p></div>
                  <div className="panel inset metric-panel"><h3>OWASP buckets</h3><p>{Object.keys(selectedScan.summary?.owasp_top_10 || {}).length}</p></div>
                </div>

                {selectedScan.summary?.owasp_top_10 && Object.keys(selectedScan.summary.owasp_top_10).length > 0 && (
                  <div className="owasp-box">
                    <h3>OWASP Top 10 Mapping</h3>
                    {Object.entries(selectedScan.summary.owasp_top_10).map(([key, value]) => (
                      <div className="owasp-row" key={key}>
                        <span>{key}</span>
                        <strong>{value}</strong>
                      </div>
                    ))}
                  </div>
                )}

                <div className="vuln-section">
                  <h3>Verified Vulnerabilities</h3>
                  <div className="vuln-list">
                    {grouped.vulnerabilities.map((item) => (
                      <article className="vuln-card" key={item.id}>
                        <div className="vuln-head">
                          <h3>{item.title}</h3>
                          <span className={severityColor(item.severity)}>{item.severity}</span>
                        </div>
                        <p>{item.description}</p>
                        <small>{item.tool} | score {item.score ?? "-"} | {item.confidence || "unknown"} confidence | {item.owasp_category || "Unmapped"} | {item.file || "n/a"}</small>
                        {item.evidence && <pre className="evidence-box">{item.evidence}</pre>}
                        <div className="suggested-fixes">
                          <h4>Suggested fixes</h4>
                          <ul>
                            {getSuggestedFixes(item).map((fix) => (
                              <li key={fix}>{fix}</li>
                            ))}
                          </ul>
                        </div>
                      </article>
                    ))}
                    {!grouped.vulnerabilities.length && <p>{selectedScan.summary?.note || "No verified vulnerabilities stored for this scan."}</p>}
                  </div>
                </div>

                <div className="vuln-section">
                  <h3>Observations</h3>
                  <div className="vuln-list">
                    {grouped.observations.map((item) => (
                      <article className="vuln-card observation" key={item.id}>
                        <div className="vuln-head">
                          <h3>{item.title}</h3>
                          <span className={severityColor(item.severity)}>{item.severity}</span>
                        </div>
                        <p>{item.description}</p>
                        <small>{item.tool} | score {item.score ?? "-"} | {item.confidence || "unknown"} confidence | {item.file || "n/a"}</small>
                      </article>
                    ))}
                    {!grouped.observations.length && <p>No observations captured for this scan.</p>}
                  </div>
                </div>

                {(selectedScan.error_message || selectedScan.stderr_log || selectedScan.stdout_log) && (
                  <div className="logs">
                    <h3>Execution Logs</h3>
                    {selectedScan.error_message && <pre>{selectedScan.error_message}</pre>}
                    {selectedScan.stderr_log && <pre>{selectedScan.stderr_log}</pre>}
                    {selectedScan.stdout_log && <pre>{selectedScan.stdout_log}</pre>}
                  </div>
                )}
              </>
            ) : (
              <p>Select a scan to inspect the parsed findings and logs.</p>
            )}
          </motion.section>
        </div>
      );
    }

    if (view === "docs") {
      return (
        <motion.section className="panel docs-panel" initial="hidden" animate="show" variants={stagger}>
          <motion.div variants={reveal}>
            <h2>Agniscan MVP Documentation</h2>
            <p className="lede">
              Agniscan is a red-team validation suite that runs SAST on repositories and DAST against live targets.
              It fuses Semgrep, Bandit, Nmap, Nuclei, Nikto, and OWASP-focused checks into a single operator dashboard.
            </p>
          </motion.div>
          <motion.div className="docs-grid" variants={stagger}>
            <motion.div className="panel inset" variants={reveal}>
              <h3>What it does</h3>
              <p>Launch SAST or DAST scans, track progress, and export reports in HTML/PDF/JSON.</p>
              <p>Findings are mapped to OWASP Top 10 and severity-scored for prioritization.</p>
            </motion.div>
            <motion.div className="panel inset" variants={reveal}>
              <h3>Operator flow</h3>
              <p>1. Choose scan type and target.</p>
              <p>2. Observe live progress and logs.</p>
              <p>3. Review verified vulnerabilities with suggested fixes.</p>
            </motion.div>
            <motion.div className="panel inset" variants={reveal}>
              <h3>Security posture</h3>
              <p>Inputs are sanitized. Commands are invoked safely. Results are stored in SQLite.</p>
              <p>Admin access unlocks global metrics and full scan control.</p>
            </motion.div>
          </motion.div>
        </motion.section>
      );
    }

    return (
      <>
        <motion.section
          className="hero-banner panel"
          initial={{ opacity: 0, y: 30, rotateX: 8 }}
          animate={{ opacity: 1, y: 0, rotateX: 0 }}
          transition={{ duration: 0.72, ease: [0.22, 1, 0.36, 1] }}
        >
          <motion.div className="hero-copy" initial={{ opacity: 0, x: -18 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.08, duration: 0.56 }}>
            <p className="eyebrow">Live Mission Feed</p>
            <h2>Precision scanning with a hotter signal and less noise</h2>
            <p className="lede">
              Agniscan fuses SAST, Nmap reconnaissance, Nuclei templates, Nikto verification, and
              OWASP-focused web analysis into a single operator workspace.
            </p>
            <div className="hero-stat-row">
              <div className="hero-stat">
                <strong>{scans.length}</strong>
                <span>Mission records</span>
              </div>
              <div className="hero-stat">
                <strong>{Object.values(tools).filter((tool) => tool.installed).length}</strong>
                <span>Active engines</span>
              </div>
              <div className="hero-stat">
                <strong>{selectedScan?.summary?.total_vulnerabilities ?? summary?.total_vulnerabilities ?? 0}</strong>
                <span>Tracked findings</span>
              </div>
            </div>
          </motion.div>
          <motion.div
            className="hero-visual"
            aria-hidden="true"
            animate={{ y: [0, -10, 0], rotateY: [-4, 4, -4] }}
            transition={{ duration: 9, repeat: Infinity, ease: "easeInOut" }}
          >
            <div className="hero-orbit orbit-one" />
            <div className="hero-orbit orbit-two" />
            <div className="hero-image-shell">
              <div className="hero-image-glow" />
              <img className="hero-image" src="/agniscan-bot.png" alt="Agniscan assistant robot" />
            </div>
          </motion.div>
        </motion.section>

        <motion.section className="tool-strip" initial="hidden" animate="show" variants={stagger}>
          {Object.entries(tools).map(([tool, info]) => (
            <motion.div
              className={`tool-card ${info.installed ? "ready" : "missing"}`}
              key={tool}
              variants={reveal}
              whileHover={{ y: -8, rotateX: 7, rotateY: tool.length % 2 === 0 ? -5 : 5 }}
            >
              <strong>{tool}</strong>
              <span>{info.installed ? "Installed" : "Unavailable"}</span>
              {info.mode && <small>{info.mode}</small>}
            </motion.div>
          ))}
        </motion.section>

        {summary && (
          <motion.section className="summary-grid" initial="hidden" animate="show" variants={stagger}>
            <motion.div className="panel metric-panel" variants={reveal}><h3>Total scans</h3><p>{summary.total_scans}</p></motion.div>
            <motion.div className="panel metric-panel" variants={reveal}><h3>Completed</h3><p>{summary.completed_scans}</p></motion.div>
            <motion.div className="panel metric-panel" variants={reveal}><h3>Failed</h3><p>{summary.failed_scans}</p></motion.div>
            <motion.div className="panel metric-panel" variants={reveal}><h3>Verified vulnerabilities</h3><p>{summary.total_vulnerabilities}</p></motion.div>
          </motion.section>
        )}
      </>
    );
  };

  return (
    <div className="app-shell">
      <motion.header className="topbar" initial="hidden" animate="show" variants={stagger}>
        <motion.div className="brand-lockup" variants={reveal}>
          <FlameMark compact />
          <div className="brand-stack">
            <p className="eyebrow">Agniscan Control Deck</p>
            <h1>Agniscan</h1>
            <p className="lede">Real red-team scanning for code, web exposure, and OWASP-mapped findings.</p>
          </div>
        </motion.div>
        <motion.nav className="topbar-nav" variants={reveal}>
          <a className={view === "overview" ? "active" : ""} href="#/overview">Overview</a>
          <a className={view === "scans" ? "active" : ""} href="#/scans">Scans</a>
          <a className={view === "findings" ? "active" : ""} href="#/findings">Findings</a>
          <a className={view === "docs" ? "active" : ""} href="#/docs">Docs</a>
        </motion.nav>
        <motion.div className="topbar-actions" variants={reveal}>
          <div className="user-chip">
            {session.username} <span>{session.role}</span>
          </div>
          <button
            className="ghost-button"
            onClick={() => {
              clearSession();
              window.location.reload();
            }}
          >
            Logout
          </button>
        </motion.div>
      </motion.header>

      <motion.main className="page-shell" initial="hidden" animate="show" variants={stagger}>
        <ViewPanel />
      </motion.main>
    </div>
  );
}

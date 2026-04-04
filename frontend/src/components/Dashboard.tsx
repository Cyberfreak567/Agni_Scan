import { useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import { api, clearSession, downloadReport, getSession } from "../lib/api";
import { UI_VERSION } from "../lib/version";
import { ScanForms } from "./ScanForms";
import { FlameMark } from "./FlameMark";

type ScanStatus = "pending" | "running" | "completed" | "failed";
type ScanType = "sast" | "dast";

interface ToolStatus {
  installed: boolean;
  path?: string | null;
  mode?: string;
}

interface ScanSummary {
  total_scans?: number;
  completed_scans?: number;
  failed_scans?: number;
  total_vulnerabilities?: number;
  total_observations?: number;
  severity_distribution?: Record<string, number>;
  owasp_top_10?: Record<string, number>;
  note?: string;
}

interface Finding {
  id: number;
  title: string;
  severity: string;
  score?: number;
  confidence?: string;
  finding_kind?: string;
  owasp_category?: string;
  file?: string;
  description?: string;
  evidence?: string;
  tool?: string;
}

interface ScanRecord {
  id: number;
  scan_type: ScanType;
  scan_mode?: string | null;
  target: string;
  status: ScanStatus;
  progress: number;
  current_stage?: string | null;
  error_message?: string | null;
  stderr_log?: string | null;
  stdout_log?: string | null;
  summary?: ScanSummary;
  vulnerabilities?: Finding[];
}

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

const severityRank: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityColor(severity: string | undefined) {
  return {
    critical: "pill critical",
    high: "pill high",
    medium: "pill medium",
    low: "pill low",
    info: "pill info",
  }[severity || ""] || "pill";
}

function statusLabel(status: ScanStatus) {
  return {
    pending: "Queued",
    running: "Running",
    completed: "Completed",
    failed: "Failed",
  }[status];
}

function groupFindings(items: Finding[] = []) {
  return {
    vulnerabilities: items.filter((item) => item.finding_kind === "vulnerability"),
    observations: items.filter((item) => item.finding_kind !== "vulnerability"),
  };
}

function getSuggestedFixes(item: Finding) {
  const suggestions: string[] = [];
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
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null);
  const [tools, setTools] = useState<Record<string, ToolStatus>>({});
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState("overview");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [toolFilter, setToolFilter] = useState("all");
  const [searchText, setSearchText] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const pollingRef = useRef<number | null>(null);

  async function refresh(source: "auto" | "manual" = "auto") {
    try {
      const [scanData, toolData] = await Promise.all([
        api<ScanRecord[]>("/api/scans"),
        api<Record<string, ToolStatus>>("/api/scans/tools"),
      ]);
      setScans(scanData);
      setTools(toolData);
      if (scanData.length > 0) {
        const active = selectedScan ? scanData.find((item) => item.id === selectedScan.id) : scanData[0];
        if (!selectedScan || active?.id !== selectedScan.id) {
          setSelectedScan(active || scanData[0]);
        } else if (active) {
          setSelectedScan(active);
        }
      } else {
        setSelectedScan(null);
      }
      if (session.role === "admin") {
        const summaryData = await api<ScanSummary>("/api/scans/admin/summary");
        setSummary(summaryData);
      }
      setError("");
      if (source === "manual") {
        setLastUpdated(new Date());
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to refresh data.");
    } finally {
      setLoading(false);
    }
  }

  async function deleteScan(scanId: number) {
    const confirmed = window.confirm(`Delete scan #${scanId}? This will remove its findings and reports.`);
    if (!confirmed) {
      return;
    }
    try {
      await api(`/api/scans/${scanId}`, { method: "DELETE" });
      if (selectedScan?.id === scanId) {
        setSelectedScan(null);
      }
      await refresh("manual");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to delete scan.");
    }
  }

  useEffect(() => {
    refresh("manual");
  }, []);

  const hasActiveScans = scans.some((scan) => scan.status === "pending" || scan.status === "running");

  useEffect(() => {
    if (!hasActiveScans) {
      if (pollingRef.current) {
        window.clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
      return;
    }
    if (pollingRef.current) {
      return;
    }
    pollingRef.current = window.setInterval(() => refresh("auto"), 5000);
    return () => {
      if (pollingRef.current) {
        window.clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    };
  }, [hasActiveScans]);

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

  const toolOptions = useMemo(() => {
    const items = new Set<string>();
    (selectedScan?.vulnerabilities || []).forEach((finding) => {
      if (finding.tool) {
        items.add(finding.tool);
      }
    });
    return Array.from(items);
  }, [selectedScan?.vulnerabilities]);

  const filteredVulns = useMemo(() => {
    const query = searchText.toLowerCase();
    return grouped.vulnerabilities
      .filter((item) => (severityFilter === "all" ? true : item.severity === severityFilter))
      .filter((item) => (toolFilter === "all" ? true : item.tool === toolFilter))
      .filter((item) => (query ? `${item.title} ${item.description} ${item.tool}`.toLowerCase().includes(query) : true))
      .sort((a, b) => (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99));
  }, [grouped.vulnerabilities, searchText, severityFilter, toolFilter]);

  const normalizedProgress =
    selectedScan?.status === "completed" ? 100 : selectedScan?.status === "failed" ? 100 : selectedScan?.progress ?? 0;

  const showReports = selectedScan?.status === "completed";

  const ViewPanel = () => {
    if (view === "scans") {
      return (
        <>
          <ScanForms onCreated={() => refresh("manual")} />
          {error && <div className="error-banner">{error}</div>}
          <div className="content-grid">
            <motion.section className="panel" initial={{ opacity: 0, x: -24 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.58 }}>
              <div className="panel-title-row">
                <h2>All Scans</h2>
                <button className="ghost-button" onClick={() => refresh("manual")}>Refresh</button>
              </div>
              <motion.div className="scan-list" initial="hidden" animate="show" variants={stagger}>
                {loading && (
                  <div className="scan-skeleton">
                    <div className="skeleton-line" />
                    <div className="skeleton-line" />
                    <div className="skeleton-line short" />
                  </div>
                )}
                {scans.map((scan) => (
                  <motion.div
                    key={scan.id}
                    className={`scan-row ${selectedScan?.id === scan.id ? "active" : ""}`}
                    variants={reveal}
                    whileHover={{ y: -6, rotateX: 3 }}
                    layout
                  >
                    <button type="button" className="scan-select" onClick={() => setSelectedScan(scan)}>
                      <div className="scan-header">
                        <strong>#{scan.id}</strong> {scan.scan_type.toUpperCase()} {scan.scan_mode ? `(${scan.scan_mode})` : ""}
                        <span className={`status-pill ${scan.status}`}>{statusLabel(scan.status)}</span>
                      </div>
                      <div className="scan-target">{scan.target}</div>
                      <div className="scan-meta-line">
                        <span>{scan.current_stage || "Queued"}</span>
                        <span>{scan.progress}%</span>
                      </div>
                    </button>
                    <button type="button" className="ghost-button delete-button" onClick={() => deleteScan(scan.id)}>Delete</button>
                  </motion.div>
                ))}
                {!scans.length && !loading && <p>No scans yet.</p>}
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
                  <div><span>Status</span><strong>{statusLabel(selectedScan.status)}</strong></div>
                  <div><span>Mode</span><strong>{selectedScan.scan_mode || "-"}</strong></div>
                  <div><span>Stage</span><strong>{selectedScan.current_stage || "-"}</strong></div>
                </div>
                <div className="progress-track">
                  <motion.div
                    className={`progress-bar ${selectedScan.status}`}
                    initial={{ width: 0 }}
                    animate={{ width: `${normalizedProgress}%` }}
                    transition={{ duration: 0.7, ease: "easeOut" }}
                  />
                </div>
                {!showReports && (
                  <div className="status-banner">
                    Reports are available once the scan completes.
                  </div>
                )}
                {showReports && (
                  <div className="report-actions report-actions-ready">
                    <button type="button" onClick={async () => {
                      try { await downloadReport(`/api/reports/${selectedScan.id}/html`, `scan_${selectedScan.id}.html`); } catch (err) { setError(err instanceof Error ? err.message : "Download failed."); }
                    }}>
                      <span className="icon">{"</>"}</span>
                      HTML
                    </button>
                    <button type="button" onClick={async () => {
                      try { await downloadReport(`/api/reports/${selectedScan.id}/pdf`, `scan_${selectedScan.id}.pdf`); } catch (err) { setError(err instanceof Error ? err.message : "Download failed."); }
                    }}>
                      <span className="icon">PDF</span>
                      PDF
                    </button>
                    <button type="button" onClick={async () => {
                      try { await downloadReport(`/api/reports/${selectedScan.id}/json`, `scan_${selectedScan.id}.json`); } catch (err) { setError(err instanceof Error ? err.message : "Download failed."); }
                    }}>
                      <span className="icon">{"{ }"}</span>
                      JSON
                    </button>
                    <button type="button" className="ghost-button delete-button" onClick={() => deleteScan(selectedScan.id)}>Delete</button>
                  </div>
                )}

                {selectedScan.status === "failed" && (
                  <div className="error-banner">
                    Scan failed. {selectedScan.error_message || "Check execution logs for details."}
                  </div>
                )}

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

                <div className="filter-bar">
                  <div>
                    <label>Severity</label>
                    <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                      <option value="all">All</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                  </div>
                  <div>
                    <label>Source</label>
                    <select value={toolFilter} onChange={(event) => setToolFilter(event.target.value)}>
                      <option value="all">All</option>
                      {toolOptions.map((tool) => (
                        <option key={tool} value={tool}>{tool}</option>
                      ))}
                    </select>
                  </div>
                  <div className="search-field">
                    <label>Search</label>
                    <input
                      value={searchText}
                      onChange={(event) => setSearchText(event.target.value)}
                      placeholder="Filter findings..."
                    />
                  </div>
                </div>

                <div className="vuln-section">
                  <h3>Verified Vulnerabilities</h3>
                  <div className="vuln-list">
                    {filteredVulns.map((item) => (
                      <article className="vuln-card" key={item.id}>
                        <div className="vuln-head">
                          <div>
                            <h3>{item.title}</h3>
                            <small className="muted">{item.tool} • {item.owasp_category || "Unmapped"}</small>
                          </div>
                          <span className={severityColor(item.severity)}>{item.severity}</span>
                        </div>
                        <p>{item.description}</p>
                        <small>{item.tool} | score {item.score ?? "-"} | {item.confidence || "unknown"} confidence | {item.file || "n/a"}</small>
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
                    {!filteredVulns.length && <p>{selectedScan.summary?.note || "No verified vulnerabilities stored for this scan."}</p>}
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
            <motion.div className="panel metric-panel" variants={reveal}><h3>Total scans</h3><p>{summary.total_scans ?? scans.length}</p></motion.div>
            <motion.div className="panel metric-panel" variants={reveal}><h3>Completed</h3><p>{scans.filter((scan) => scan.status === "completed").length}</p></motion.div>
            <motion.div className="panel metric-panel" variants={reveal}><h3>Failed</h3><p>{scans.filter((scan) => scan.status === "failed").length}</p></motion.div>
            <motion.div className="panel metric-panel" variants={reveal}><h3>Verified vulnerabilities</h3><p>{summary.total_vulnerabilities ?? 0}</p></motion.div>
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
          <button className="ghost-button" onClick={() => refresh("manual")}>Refresh</button>
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

      {lastUpdated && (
        <div className="status-banner subtle">
          Last refreshed at {lastUpdated.toLocaleTimeString()}
        </div>
      )}

      <motion.main className="page-shell" initial="hidden" animate="show" variants={stagger}>
        <ViewPanel />
      </motion.main>

      <footer className="app-footer">
        <span>{UI_VERSION}</span>
      </footer>
    </div>
  );
}

import { useEffect, useState } from "react";
import { api, clearSession, downloadReport, getSession } from "../lib/api";
import { ScanForms } from "./ScanForms";
import { FlameMark } from "./FlameMark";

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

export function Dashboard() {
  const session = getSession();
  const [summary, setSummary] = useState(null);
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [tools, setTools] = useState({});
  const [error, setError] = useState("");

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

  const grouped = groupFindings(selectedScan?.vulnerabilities || []);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <FlameMark compact />
          <div className="brand-stack">
            <p className="eyebrow">Agniscan Control Deck</p>
            <h1>Agniscan</h1>
            <p className="lede">Real red-team scanning for code, web exposure, and OWASP-mapped findings.</p>
          </div>
        </div>
        <div className="topbar-actions">
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
        </div>
      </header>

      <section className="hero-banner panel">
        <div>
          <p className="eyebrow">Live Mission Feed</p>
          <h2>Precision scanning with a hotter signal and less noise</h2>
          <p className="lede">
            Agniscan fuses SAST, Nmap reconnaissance, Nuclei templates, Nikto verification, and
            OWASP-focused web analysis into a single operator workspace.
          </p>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <div className="hero-orbit orbit-one" />
          <div className="hero-orbit orbit-two" />
          <div className="hero-image-shell">
            <div className="hero-image-glow" />
            <img className="hero-image" src="/agniscan-bot.png" alt="Agniscan assistant robot" />
          </div>
        </div>
      </section>

      <section className="tool-strip">
        {Object.entries(tools).map(([tool, info]) => (
          <div className={`tool-card ${info.installed ? "ready" : "missing"}`} key={tool}>
            <strong>{tool}</strong>
            <span>{info.installed ? "Installed" : "Unavailable"}</span>
            {info.mode && <small>{info.mode}</small>}
          </div>
        ))}
      </section>

      {summary && (
        <section className="summary-grid">
          <div className="panel"><h3>Total scans</h3><p>{summary.total_scans}</p></div>
          <div className="panel"><h3>Completed</h3><p>{summary.completed_scans}</p></div>
          <div className="panel"><h3>Failed</h3><p>{summary.failed_scans}</p></div>
          <div className="panel"><h3>Verified vulnerabilities</h3><p>{summary.total_vulnerabilities}</p></div>
        </section>
      )}

      <ScanForms onCreated={refresh} />
      {error && <div className="error-banner">{error}</div>}

      <div className="content-grid">
        <section className="panel">
          <h2>All Scans</h2>
          <div className="scan-list">
            {scans.map((scan) => (
              <div key={scan.id} className={`scan-row ${selectedScan?.id === scan.id ? "active" : ""}`}>
                <button type="button" className="scan-select" onClick={() => setSelectedScan(scan)}>
                  <div><strong>#{scan.id}</strong> {scan.scan_type.toUpperCase()} {scan.scan_mode ? `(${scan.scan_mode})` : ""}</div>
                  <div>{scan.target}</div>
                  <div>{scan.status}</div>
                  <div>{scan.current_stage || "Queued"}</div>
                  <div>{scan.progress}%</div>
                </button>
                <button type="button" className="ghost-button delete-button" onClick={() => deleteScan(scan.id)}>Delete</button>
              </div>
            ))}
            {!scans.length && <p>No scans yet.</p>}
          </div>
        </section>

        <section className="panel detail-panel">
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
                <div className="progress-bar" style={{ width: `${selectedScan.progress}%` }} />
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
                <div className="panel inset"><h3>Verified vulnerabilities</h3><p>{selectedScan.summary?.total_vulnerabilities ?? 0}</p></div>
                <div className="panel inset"><h3>Observations</h3><p>{selectedScan.summary?.total_observations ?? 0}</p></div>
                <div className="panel inset"><h3>High + Critical</h3><p>{(selectedScan.summary?.severity_distribution?.high ?? 0) + (selectedScan.summary?.severity_distribution?.critical ?? 0)}</p></div>
                <div className="panel inset"><h3>OWASP buckets</h3><p>{Object.keys(selectedScan.summary?.owasp_top_10 || {}).length}</p></div>
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
        </section>
      </div>
    </div>
  );
}

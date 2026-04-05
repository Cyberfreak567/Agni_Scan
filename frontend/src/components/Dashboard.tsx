import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  ArrowDownTrayIcon,
  ArrowPathIcon,
  BoltIcon,
  CheckCircleIcon,
  CodeBracketSquareIcon,
  CpuChipIcon,
  ExclamationTriangleIcon,
  FunnelIcon,
  GlobeAltIcon,
  MagnifyingGlassIcon,
  ShieldExclamationIcon,
  ShieldCheckIcon,
  ServerStackIcon,
  TrashIcon,
} from "@heroicons/react/24/outline";

import { api, clearSession, downloadReport, getSession } from "../lib/api";
import { FlameMark } from "./FlameMark";
import { Charts } from "./Charts";
import type { Finding, ScanRecord, ScanSummary, ToolStatus } from "./types";
import { Modal } from "./ui/Modal";
import { Spinner } from "./ui/Spinner";
import { Toast, type ToastMessage } from "./ui/Toast";
import { ScanForms } from "./ScanForms";

type ViewKey = "overview" | "scans" | "findings" | "docs";

const viewLabels: Record<ViewKey, string> = {
  overview: "Overview",
  scans: "Scans",
  findings: "Findings",
  docs: "Docs",
};

const severityOrder = ["critical", "high", "medium", "low", "info"] as const;

function formatWhen(value?: string | null) {
  if (!value) return "n/a";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function normalizeSeverity(value?: string | null) {
  if (!value) return "info";
  return value.toLowerCase();
}

function useHashRoute() {
  const [view, setView] = useState<ViewKey>(() => {
    const hash = window.location.hash.replace("#/", "");
    if (hash === "scans" || hash === "findings" || hash === "docs") return hash;
    return "overview";
  });

  useEffect(() => {
    const handler = () => {
      const hash = window.location.hash.replace("#/", "");
      if (hash === "scans" || hash === "findings" || hash === "docs") {
        setView(hash);
      } else {
        setView("overview");
      }
    };
    window.addEventListener("hashchange", handler);
    return () => window.removeEventListener("hashchange", handler);
  }, []);

  const navigate = useCallback((next: ViewKey) => {
    window.location.hash = `/${next}`;
    setView(next);
  }, []);

  return { view, navigate };
}

export function Dashboard() {
  const { view, navigate } = useHashRoute();
  const { username, role } = getSession();

  const [tools, setTools] = useState<Record<string, ToolStatus>>({});
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [downloadOpen, setDownloadOpen] = useState(false);
  const [downloadLoading, setDownloadLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const previousStatuses = useRef<Map<number, string>>(new Map());

  const scansInProgress = useMemo(
    () => scans.some((scan) => scan.status === "pending" || scan.status === "running"),
    [scans]
  );

  const activeScan = useMemo(
    () => scans.find((scan) => scan.id === activeScanId) ?? scans[0] ?? null,
    [activeScanId, scans]
  );

  const findings = activeScan?.vulnerabilities ?? [];

  const sources = useMemo(() => {
    const bucket = new Set<string>();
    findings.forEach((item) => {
      if (item.tool) bucket.add(item.tool);
    });
    return Array.from(bucket).sort((a, b) => a.localeCompare(b));
  }, [findings]);

  useEffect(() => {
    const handle = window.setTimeout(() => setDebouncedSearch(search), 250);
    return () => window.clearTimeout(handle);
  }, [search]);

  const addToast = useCallback((toast: Omit<ToastMessage, "id">) => {
    const id = typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
    setToasts((prev) => [...prev, { ...toast, id }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id));
    }, 4200);
  }, []);

  const fetchData = useCallback(
    async (opts: { silent?: boolean } = {}) => {
      const silent = opts.silent ?? false;
      if (!silent) {
        setRefreshing(true);
      }
      setError(null);
      try {
        const [toolsData, scansData] = await Promise.all([
          api<Record<string, ToolStatus>>("/api/scans/tools"),
          api<ScanRecord[]>("/api/scans"),
        ]);

        setTools((prev) => (JSON.stringify(prev) === JSON.stringify(toolsData) ? prev : toolsData));
        setScans((prev) => (JSON.stringify(prev) === JSON.stringify(scansData) ? prev : scansData));
        if (role === "admin") {
          const summaryData = await api<ScanSummary>("/api/scans/admin/summary");
          setSummary(summaryData);
        } else {
          setSummary(null);
        }

        if (!silent) {
          setLastUpdated(new Date());
        }

        const statusMap = new Map<number, string>();
        scansData.forEach((scan) => statusMap.set(scan.id, scan.status));
        const prevMap = previousStatuses.current;
        scansData.forEach((scan) => {
          const before = prevMap.get(scan.id);
          if (before && before !== scan.status) {
            if (scan.status === "completed") {
              addToast({ type: "success", message: `Scan #${scan.id} completed.` });
            }
            if (scan.status === "failed") {
              addToast({ type: "error", message: `Scan #${scan.id} failed.` });
            }
          }
        });
        previousStatuses.current = statusMap;
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unable to refresh data.");
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [addToast, role]
  );

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    if (!autoRefresh || !scansInProgress) return;
    if (view !== "scans" && view !== "findings") return;
    const handle = window.setInterval(() => {
      fetchData({ silent: true });
    }, 45000);
    return () => window.clearInterval(handle);
  }, [autoRefresh, scansInProgress, view, fetchData]);

  useEffect(() => {
    if (scansInProgress) {
      setAutoRefresh(true);
    }
  }, [scansInProgress]);

  useEffect(() => {
    if (activeScanId === null && scans[0]) {
      setActiveScanId(scans[0].id);
    }
  }, [activeScanId, scans]);

  const filteredFindings = useMemo(() => {
    const query = debouncedSearch.trim().toLowerCase();
    return findings.filter((item) => {
      if (severityFilter !== "all" && normalizeSeverity(item.severity) !== severityFilter) {
        return false;
      }
      if (sourceFilter !== "all" && item.tool !== sourceFilter) {
        return false;
      }
      if (!query) return true;
      const hay = `${item.title} ${item.description ?? ""} ${item.file ?? ""} ${item.tool ?? ""}`.toLowerCase();
      return hay.includes(query);
    });
  }, [findings, severityFilter, sourceFilter, debouncedSearch]);

  const severityCount = useMemo(() => {
    const bucket: Record<string, number> = {};
    findings.forEach((item) => {
      const key = normalizeSeverity(item.severity);
      bucket[key] = (bucket[key] || 0) + 1;
    });
    return bucket;
  }, [findings]);

  const onDeleteScan = async (scanId: number) => {
    if (!window.confirm(`Delete scan #${scanId}? This cannot be undone.`)) return;
    try {
      await api(`/api/scans/${scanId}`, { method: "DELETE" });
      addToast({ type: "success", message: `Deleted scan #${scanId}.` });
      await fetchData();
    } catch (err) {
      addToast({ type: "error", message: err instanceof Error ? err.message : "Unable to delete scan." });
    }
  };

  const runDownload = async (format: "html" | "pdf" | "json") => {
    if (!activeScan) return;
    setDownloadLoading(true);
    try {
      await downloadReport(`/api/reports/${activeScan.id}/${format}`, `scan_${activeScan.id}.${format}`);
      addToast({ type: "success", message: `Report ${format.toUpperCase()} downloaded.` });
      setDownloadOpen(false);
    } catch (err) {
      addToast({ type: "error", message: err instanceof Error ? err.message : "Download failed." });
    } finally {
      setDownloadLoading(false);
    }
  };

  const toggleExpanded = (id: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const statusTone = (status?: string | null) => {
    if (status === "completed") return "text-emerald-200 bg-emerald-500/20";
    if (status === "failed") return "text-red-200 bg-red-500/20";
    if (status === "running") return "text-amber-200 bg-amber-500/20";
    return "text-slate-200 bg-white/10";
  };

  const toolCards = useMemo(() => {
    const meta: Record<string, { label: string; description: string; Icon: typeof CpuChipIcon }> = {
      semgrep: { label: "Semgrep", description: "Static code pattern analyzer", Icon: CodeBracketSquareIcon },
      bandit: { label: "Bandit", description: "Python security linting", Icon: ShieldExclamationIcon },
      "owasp-web": { label: "OWASP Web", description: "Active HTTP safety checks", Icon: GlobeAltIcon },
      nuclei: { label: "Nuclei", description: "Template-driven web probing", Icon: BoltIcon },
      nmap: { label: "Nmap", description: "Network reconnaissance engine", Icon: ServerStackIcon },
      nikto: { label: "Nikto", description: "Web server hardening checks", Icon: CpuChipIcon },
    };
    return Object.entries(tools).map(([key, value]) => {
      const fallback = meta[key] || { label: key, description: "Security tool", Icon: ShieldCheckIcon };
      return { key, installed: value.installed, ...fallback };
    });
  }, [tools]);

  const viewTransition = {
    initial: { opacity: 0, y: 18 },
    animate: { opacity: 1, y: 0, transition: { duration: 0.35, ease: "easeOut" } },
    exit: { opacity: 0, y: 18, transition: { duration: 0.2 } },
  };

  return (
    <div className="app-shell min-h-screen pb-20 text-ink">
      <Toast items={toasts} onDismiss={(id) => setToasts((prev) => prev.filter((item) => item.id !== id))} />
      <header className="sticky top-0 z-40 bg-gradient-to-b from-[#04090f]/95 via-[#04090f]/80 to-transparent backdrop-blur-xl">
        <div className="flex flex-wrap items-center gap-4 px-6 py-4 md:px-12">
          <div className="flex items-center gap-4">
            <FlameMark compact />
            <div>
              <p className="text-xs uppercase tracking-[0.35em] text-muted">Agniscan Control Deck</p>
              <h1 className="text-4xl font-semibold text-white">Agniscan</h1>
              <p className="mt-1 max-w-sm text-sm text-muted">
                Real red-team scanning for code, web exposure, and OWASP-mapped findings.
              </p>
            </div>
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-3">
            <nav className="flex items-center gap-2 rounded-full border border-white/10 bg-white/5 p-1 text-sm">
              {Object.entries(viewLabels).map(([key, label]) => (
                <button
                  key={key}
                  className={`rounded-full px-4 py-2 transition ${
                    view === key ? "bg-accent text-slate-900 shadow-lg" : "text-ink/70 hover:text-white"
                  }`}
                  onClick={() => navigate(key as ViewKey)}
                >
                  {label}
                </button>
              ))}
            </nav>
            <button className="btn-ghost" onClick={() => fetchData()} disabled={refreshing} title="Refresh data">
              {refreshing ? <Spinner size={16} /> : <ArrowPathIcon className="h-4 w-4" />} Refresh
            </button>
            <div className="glass-panel flex items-center gap-2 px-4 py-2 text-sm">
              <ShieldCheckIcon className="h-4 w-4 text-neon" />
              <span>{username ?? "analyst"}</span>
              <span className="text-accentGlow">{role ?? "user"}</span>
            </div>
            <button className="btn-ghost" onClick={() => { clearSession(); window.location.reload(); }}>
              Logout
            </button>
          </div>
        </div>
      </header>

      <main className="px-6 md:px-12">
        <div className="mt-5 flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
          <span>Last refreshed at {lastUpdated ? lastUpdated.toLocaleTimeString() : "n/a"}</span>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-muted">
              <input type="checkbox" checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} />
              Auto refresh
            </label>
            {scansInProgress && (
              <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-amber-200">
                Active scans running
              </span>
            )}
          </div>
        </div>

        {error && (
          <div className="mt-4 rounded-2xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {error}
          </div>
        )}

        <AnimatePresence mode="wait">
          {view === "overview" && (
            <motion.section key="overview" {...viewTransition} className="mt-10 space-y-12">
              <div className="glass-panel grid gap-8 p-10 lg:grid-cols-[1.25fr,0.75fr]">
                <div>
                  <p className="text-xs uppercase tracking-[0.35em] text-accentGlow">Live mission feed</p>
                  <h2 className="mt-3 text-5xl font-semibold text-white drop-shadow-[0_0_18px_rgba(108,229,255,0.35)]">
                    Precision scanning with a hotter signal and less noise
                  </h2>
                  <p className="mt-4 max-w-2xl text-lg text-muted">
                    Agniscan fuses SAST, Nmap reconnaissance, Nuclei templates, Nikto verification, and OWASP-focused web
                    analysis into a single operator workspace.
                  </p>
                  <div className="mt-8 grid gap-5 sm:grid-cols-3">
                    <div className="glass-card p-6">
                      <div className="flex items-center gap-3 text-muted">
                        <ShieldCheckIcon className="h-5 w-5 text-neon" />
                        <p className="text-xs uppercase tracking-[0.2em]">Mission records</p>
                      </div>
                      <p className="mt-3 text-3xl font-semibold text-white">{summary?.total_scans ?? scans.length}</p>
                    </div>
                    <div className="glass-card p-6">
                      <div className="flex items-center gap-3 text-muted">
                        <BoltIcon className="h-5 w-5 text-accentGlow" />
                        <p className="text-xs uppercase tracking-[0.2em]">Active engines</p>
                      </div>
                      <p className="mt-3 text-3xl font-semibold text-white">{Object.keys(tools).length || 0}</p>
                    </div>
                    <div className="glass-card p-6">
                      <div className="flex items-center gap-3 text-muted">
                        <ExclamationTriangleIcon className="h-5 w-5 text-warn" />
                        <p className="text-xs uppercase tracking-[0.2em]">Tracked findings</p>
                      </div>
                      <p className="mt-3 text-3xl font-semibold text-white">
                        {summary?.total_vulnerabilities ?? findings.length}
                      </p>
                    </div>
                  </div>
                </div>
                <motion.div
                  initial={{ opacity: 0, x: 30 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.6, ease: "easeOut" }}
                  className="glass-card flex items-center justify-center p-6"
                >
                  <img
                    src="/agniscan-bot.png"
                    alt="Agniscan bot"
                    className="max-h-96 w-full rounded-3xl object-cover shadow-glow"
                    onError={(event) => {
                      event.currentTarget.style.display = "none";
                    }}
                  />
                </motion.div>
              </div>

              <div className="grid gap-6 md:grid-cols-3">
                {toolCards.map((tool) => (
                  <motion.div key={tool.key} whileHover={{ y: -6, scale: 1.02 }} className="glass-card p-6">
                    <div className="flex items-start justify-between">
                      <div>
                        <tool.Icon className="h-6 w-6 text-neon" />
                        <p className="mt-3 text-lg font-semibold text-white">{tool.label}</p>
                        <p className="mt-1 text-sm text-muted">{tool.description}</p>
                      </div>
                      <span
                        className={`status-pill ${
                          tool.installed ? "text-emerald-200 bg-emerald-500/20" : "text-red-200 bg-red-500/20"
                        }`}
                      >
                        {tool.installed ? "Active" : "Ready"}
                      </span>
                    </div>
                  </motion.div>
                ))}
              </div>

              <Charts scans={scans} summary={summary} findings={findings} />
            </motion.section>
          )}

          {view === "scans" && (
            <motion.section key="scans" {...viewTransition} className="mt-10 space-y-10">
              <ScanForms onCreated={() => fetchData()} />
              <div className="grid gap-6 lg:grid-cols-[1.1fr,1fr]">
                <div className="glass-panel p-6">
                  <div className="flex items-center justify-between">
                    <h3 className="text-2xl font-semibold text-white">All scans</h3>
                    <span className="text-xs uppercase text-muted">{scans.length} total</span>
                  </div>
                  <div className="mt-5 space-y-4">
                    {loading && (
                      <div className="space-y-3">
                        {[0, 1, 2].map((item) => (
                          <div key={item} className="skeleton h-20" />
                        ))}
                      </div>
                    )}
                    {!loading && scans.length === 0 && (
                      <div className="rounded-2xl border border-white/10 bg-white/5 p-6 text-sm text-muted">
                        No scans yet. Launch a scan to populate the feed.
                      </div>
                    )}
                    {scans.map((scan) => (
                      <button
                        key={scan.id}
                        className={`w-full rounded-2xl border px-4 py-4 text-left transition ${
                          activeScan?.id === scan.id
                            ? "border-accentGlow bg-white/10 shadow-glow"
                            : "border-white/10 bg-white/5 hover:border-white/20"
                        }`}
                        onClick={() => setActiveScanId(scan.id)}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <p className="text-sm uppercase text-muted">#{scan.id} {scan.scan_type.toUpperCase()}</p>
                            <p className="mt-1 text-sm text-white/80 break-all">{scan.target}</p>
                            <p className="mt-2 text-xs text-muted">{formatWhen(scan.created_at)}</p>
                          </div>
                          <span className={`status-pill ${statusTone(scan.status)}`}>{scan.status}</span>
                        </div>
                        <div className="mt-3 h-2 w-full rounded-full bg-white/10">
                          <div
                            className="h-2 rounded-full bg-gradient-to-r from-accent to-accentGlow transition-all"
                            style={{ width: `${Math.min(100, scan.status === "completed" ? 100 : scan.progress ?? 0)}%` }}
                          />
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
                <div className="glass-panel p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs uppercase text-muted">Detailed report</p>
                      <h3 className="text-2xl font-semibold text-white">
                        {activeScan ? `Scan #${activeScan.id}` : "Select a scan"}
                      </h3>
                    </div>
                    {activeScan && (
                      <button className="btn-ghost" onClick={() => onDeleteScan(activeScan.id)}>
                        <TrashIcon className="h-4 w-4" /> Delete
                      </button>
                    )}
                  </div>
                  {activeScan ? (
                    <div className="mt-5 space-y-4">
                      <div className="grid gap-4 sm:grid-cols-2">
                        <div className="glass-card p-4">
                          <p className="text-xs uppercase text-muted">Target</p>
                          <p className="mt-2 text-sm text-white/80 break-all">{activeScan.target}</p>
                        </div>
                        <div className="glass-card p-4">
                          <p className="text-xs uppercase text-muted">Stage</p>
                          <p className="mt-2 text-sm text-white/80">{activeScan.current_stage ?? "n/a"}</p>
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div className="flex items-center gap-2">
                          {activeScan.status === "completed" ? (
                            <CheckCircleIcon className="h-5 w-5 text-emerald-300" />
                          ) : activeScan.status === "failed" ? (
                            <ExclamationTriangleIcon className="h-5 w-5 text-red-300" />
                          ) : (
                            <Spinner />
                          )}
                          <span className="text-sm text-white/80">{activeScan.status}</span>
                        </div>
                        {activeScan.status === "completed" ? (
                          <button className="btn-primary" onClick={() => setDownloadOpen(true)}>
                            <ArrowDownTrayIcon className="h-4 w-4" /> Reports
                          </button>
                        ) : (
                          <span className="text-xs text-muted">Reports available after completion.</span>
                        )}
                      </div>
                      <div className="grid gap-4 sm:grid-cols-3">
                        <div className="glass-card p-4">
                          <p className="text-xs uppercase text-muted">Verified vulnerabilities</p>
                          <p className="mt-2 text-2xl font-semibold text-white">
                            {activeScan.summary?.total_vulnerabilities ?? findings.length}
                          </p>
                        </div>
                        <div className="glass-card p-4">
                          <p className="text-xs uppercase text-muted">Observations</p>
                          <p className="mt-2 text-2xl font-semibold text-white">
                            {activeScan.summary?.total_observations ?? 0}
                          </p>
                        </div>
                        <div className="glass-card p-4">
                          <p className="text-xs uppercase text-muted">High + Critical</p>
                          <p className="mt-2 text-2xl font-semibold text-white">
                            {(severityCount.critical || 0) + (severityCount.high || 0)}
                          </p>
                        </div>
                      </div>
                      {activeScan.error_message && (
                        <div className="rounded-2xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
                          {activeScan.error_message}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="mt-4 rounded-2xl border border-white/10 bg-white/5 p-6 text-sm text-muted">
                      Select a scan on the left to inspect its details.
                    </div>
                  )}
                </div>
              </div>
              {role === "admin" && (
                <div className="glass-panel p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-xs uppercase text-muted">Admin visibility</p>
                      <h3 className="text-2xl font-semibold text-white">Operator activity</h3>
                    </div>
                    <span className="text-xs uppercase text-muted">{scans.length} total scans</span>
                  </div>
                  <div className="mt-5 overflow-x-auto">
                    <table className="min-w-full text-left text-sm">
                      <thead>
                        <tr className="text-xs uppercase tracking-[0.2em] text-muted">
                          <th className="py-2 pr-4">User</th>
                          <th className="py-2 pr-4">Scan</th>
                          <th className="py-2 pr-4">Target</th>
                          <th className="py-2 pr-4">Status</th>
                          <th className="py-2">Created</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-white/10">
                        {scans.map((scan) => (
                          <tr key={`admin-${scan.id}`} className="text-white/80">
                            <td className="py-3 pr-4">
                              <div className="text-sm font-semibold text-white">{scan.username ?? "unknown"}</div>
                              <div className="text-xs text-muted">{scan.user_role ?? "user"}</div>
                            </td>
                            <td className="py-3 pr-4 text-xs uppercase text-muted">
                              #{scan.id} {scan.scan_type}
                            </td>
                            <td className="py-3 pr-4 text-sm text-white/80 break-all">{scan.target}</td>
                            <td className="py-3 pr-4">
                              <span className={`status-pill ${statusTone(scan.status)}`}>{scan.status}</span>
                            </td>
                            <td className="py-3 text-xs text-muted">{formatWhen(scan.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </motion.section>
          )}

          {view === "findings" && (
            <motion.section key="findings" {...viewTransition} className="mt-10 space-y-6">
              <div className="glass-panel p-6">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="text-xs uppercase text-muted">Findings catalog</p>
                    <h3 className="text-2xl font-semibold text-white">Verified vulnerabilities</h3>
                  </div>
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="relative">
                      <MagnifyingGlassIcon className="absolute left-3 top-2.5 h-4 w-4 text-muted" />
                      <input
                        className="input-field pl-9"
                        value={search}
                        onChange={(event) => setSearch(event.target.value)}
                        placeholder="Filter findings..."
                      />
                    </div>
                    <div className="flex items-center gap-2 text-xs uppercase text-muted">
                      <FunnelIcon className="h-4 w-4" /> Filters
                    </div>
                  </div>
                </div>
                <div className="mt-4 grid gap-3 lg:grid-cols-[1fr,1fr,1fr]">
                  <select className="input-field" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                    <option value="all">All severities</option>
                    {severityOrder.map((item) => (
                      <option key={item} value={item}>{item}</option>
                    ))}
                  </select>
                  <select className="input-field" value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}>
                    <option value="all">All sources</option>
                    {sources.map((source) => (
                      <option key={source} value={source}>{source}</option>
                    ))}
                  </select>
                  <button className="btn-ghost" onClick={() => { setSeverityFilter("all"); setSourceFilter("all"); setSearch(""); }}>
                    Clear filters
                  </button>
                </div>
              </div>

              {filteredFindings.length === 0 ? (
                <div className="glass-panel p-6 text-sm text-muted">
                  No findings matched your current filters.
                </div>
              ) : (
                <div className="space-y-4">
                  {filteredFindings.map((item) => {
                    const isOpen = expanded.has(item.id);
                    const severity = normalizeSeverity(item.severity);
                    return (
                      <motion.div key={item.id} layout className="glass-card p-5" whileHover={{ y: -4 }}>
                        <button className="flex w-full flex-wrap items-start justify-between gap-3 text-left" onClick={() => toggleExpanded(item.id)}>
                          <div className="min-w-0">
                            <p className="text-base text-white/90">{item.title}</p>
                            <p className="text-xs text-muted">{item.tool || "unknown"} · {item.file || "n/a"}</p>
                          </div>
                          <span className={`tag tag-${severity}`}>{severity}</span>
                        </button>
                        <AnimatePresence>
                          {isOpen && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: "auto" }}
                              exit={{ opacity: 0, height: 0 }}
                              className="mt-3 text-sm text-muted"
                            >
                              <p>{item.description || "No description provided."}</p>
                              {item.evidence && <p className="mt-2 text-xs text-white/70">Evidence: {item.evidence}</p>}
                              <div className="mt-2 text-xs text-muted">
                                OWASP: {item.owasp_category || "n/a"} · Score: {item.score ?? "n/a"} · Confidence: {item.confidence ?? "n/a"}
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </motion.div>
                    );
                  })}
                </div>
              )}
            </motion.section>
          )}

          {view === "docs" && (
            <motion.section key="docs" {...viewTransition} className="mt-10 space-y-6">
              <div className="glass-panel p-6">
                <p className="text-xs uppercase text-muted">Documentation</p>
                <h3 className="mt-2 text-2xl font-semibold text-white">Operator playbook</h3>
                <p className="mt-3 text-sm text-muted">
                  Use Agniscan to schedule scans, review findings, and export executive reports. Results are tagged with OWASP buckets
                  and severity so stakeholders can prioritize remediation.
                </p>
                <div className="mt-4 grid gap-4 md:grid-cols-2">
                  <div className="glass-card p-4">
                    <p className="text-sm font-semibold text-white">1. Launch a scan</p>
                    <p className="text-xs text-muted">Select SAST for code repos, or DAST for live endpoints.</p>
                  </div>
                  <div className="glass-card p-4">
                    <p className="text-sm font-semibold text-white">2. Monitor progress</p>
                    <p className="text-xs text-muted">Watch stages and logs while the scan runs.</p>
                  </div>
                  <div className="glass-card p-4">
                    <p className="text-sm font-semibold text-white">3. Review findings</p>
                    <p className="text-xs text-muted">Filter by severity and tool to focus remediation.</p>
                  </div>
                  <div className="glass-card p-4">
                    <p className="text-sm font-semibold text-white">4. Export reports</p>
                    <p className="text-xs text-muted">Download JSON, HTML, or PDF for auditors.</p>
                  </div>
                </div>
              </div>
            </motion.section>
          )}
        </AnimatePresence>
      </main>

      <Modal
        open={downloadOpen}
        title={`Reports for scan #${activeScan?.id ?? "n/a"}`}
        description="Choose a report format to export. Files are generated by the backend."
        onClose={() => setDownloadOpen(false)}
      >
        {activeScan && (
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4 text-sm text-muted">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-white/80 break-all">{activeScan.target}</span>
              <span className={`status-pill ${statusTone(activeScan.status)}`}>{activeScan.status}</span>
            </div>
            <div className="mt-2 grid gap-2 text-xs text-muted sm:grid-cols-3">
              <span>Vulns: {activeScan.summary?.total_vulnerabilities ?? findings.length}</span>
              <span>Observations: {activeScan.summary?.total_observations ?? 0}</span>
              <span>Created: {formatWhen(activeScan.created_at)}</span>
            </div>
          </div>
        )}
        <div className="grid gap-3 sm:grid-cols-3">
          {["html", "pdf", "json"].map((format) => (
            <button
              key={format}
              className="btn-primary"
              onClick={() => runDownload(format as "html" | "pdf" | "json")}
              disabled={downloadLoading}
            >
              {downloadLoading ? <Spinner size={16} /> : <ArrowDownTrayIcon className="h-4 w-4" />}
              {format.toUpperCase()}
            </button>
          ))}
        </div>
      </Modal>
      <footer className="mt-16 py-10 text-center text-xs text-muted">
        Agniscan UI build {new Date().toISOString().slice(0, 10)}
      </footer>
    </div>
  );
}

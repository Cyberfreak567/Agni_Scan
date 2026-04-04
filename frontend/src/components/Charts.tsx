import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { ScanRecord, ScanSummary, Finding } from "./types";

const severityPalette: Record<string, string> = {
  critical: "#ff3d5a",
  high: "#ff7a2f",
  medium: "#f6b13d",
  low: "#6ce5ff",
  info: "#94a3b8",
};

function buildSeverityData(summary?: ScanSummary, findings?: Finding[]) {
  const distribution = summary?.severity_distribution;
  if (distribution) {
    return Object.entries(distribution).map(([key, value]) => ({
      name: key,
      value,
      fill: severityPalette[key] || "#9fb0bc",
    }));
  }
  const bucket = new Map<string, number>();
  (findings || []).forEach((item) => {
    bucket.set(item.severity, (bucket.get(item.severity) || 0) + 1);
  });
  return Array.from(bucket.entries()).map(([key, value]) => ({
    name: key,
    value,
    fill: severityPalette[key] || "#9fb0bc",
  }));
}

function buildToolData(findings?: Finding[]) {
  const bucket = new Map<string, number>();
  (findings || []).forEach((item) => {
    if (!item.tool) return;
    bucket.set(item.tool, (bucket.get(item.tool) || 0) + 1);
  });
  return Array.from(bucket.entries()).map(([tool, count]) => ({ tool, count }));
}

function buildActivityData(scans: ScanRecord[]) {
  const bucket = new Map<string, number>();
  scans.forEach((scan) => {
    const date = new Date(scan.created_at);
    if (Number.isNaN(date.getTime())) return;
    const label = date.toISOString().slice(0, 10);
    bucket.set(label, (bucket.get(label) || 0) + 1);
  });
  return Array.from(bucket.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(-7)
    .map(([date, count]) => ({ date, count }));
}

interface ChartsProps {
  scans: ScanRecord[];
  summary?: ScanSummary | null;
  findings?: Finding[];
}

export function Charts({ scans, summary, findings }: ChartsProps) {
  const severityData = buildSeverityData(summary ?? undefined, findings);
  const toolData = buildToolData(findings);
  const activityData = buildActivityData(scans);

  return (
    <div className="grid gap-6 lg:grid-cols-3">
      <div className="glass-card p-5">
        <p className="text-sm uppercase tracking-[0.2em] text-muted">Severity</p>
        <h3 className="mt-2 text-lg font-semibold text-white">Distribution</h3>
        <div className="mt-4 h-56">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} />
              <Tooltip contentStyle={{ background: "#0d1723", border: "1px solid rgba(255,255,255,0.1)" }} />
              <Legend wrapperStyle={{ color: "#e2e8f0", fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div className="glass-card p-5">
        <p className="text-sm uppercase tracking-[0.2em] text-muted">Tool activity</p>
        <h3 className="mt-2 text-lg font-semibold text-white">Findings by Tool</h3>
        <div className="mt-4 h-56">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={toolData}>
              <CartesianGrid stroke="rgba(255,255,255,0.08)" />
              <XAxis dataKey="tool" tick={{ fill: "#9fb0bc", fontSize: 12 }} />
              <YAxis tick={{ fill: "#9fb0bc", fontSize: 12 }} />
              <Tooltip contentStyle={{ background: "#0d1723", border: "1px solid rgba(255,255,255,0.1)" }} />
              <Bar dataKey="count" fill="#6ce5ff" radius={[10, 10, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div className="glass-card p-5">
        <p className="text-sm uppercase tracking-[0.2em] text-muted">Timeline</p>
        <h3 className="mt-2 text-lg font-semibold text-white">Scan Activity</h3>
        <div className="mt-4 h-56">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={activityData}>
              <CartesianGrid stroke="rgba(255,255,255,0.08)" />
              <XAxis dataKey="date" tick={{ fill: "#9fb0bc", fontSize: 12 }} />
              <YAxis tick={{ fill: "#9fb0bc", fontSize: 12 }} />
              <Tooltip contentStyle={{ background: "#0d1723", border: "1px solid rgba(255,255,255,0.1)" }} />
              <Line type="monotone" dataKey="count" stroke="#ffb347" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

export type ScanStatus = "pending" | "running" | "completed" | "failed";
export type ScanType = "sast" | "dast";

export interface ToolStatus {
  installed: boolean;
  path?: string | null;
  mode?: string;
}

export interface ScanSummary {
  total_scans?: number;
  completed_scans?: number;
  failed_scans?: number;
  total_vulnerabilities?: number;
  total_observations?: number;
  severity_distribution?: Record<string, number>;
  owasp_top_10?: Record<string, number>;
  note?: string;
}

export interface Finding {
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

export interface ScanRecord {
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
  created_at: string;
}

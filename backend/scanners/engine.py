from __future__ import annotations

import json
import logging
import threading
from collections import Counter
from pathlib import Path

from ..db import execute, execute_many, fetch_all, fetch_one, get_conn
from ..reports.generator import render_html_report, write_reports
from ..security import utc_now
from .dast import enrich_with_owasp, run_http_baseline, run_nikto, run_nmap, run_nuclei, run_owasp_web_checks
from .sast import build_sast_observations, prepare_source, run_bandit, run_semgrep, _scan_source_stats

logger = logging.getLogger("scan-engine")
RUNS_DIR = Path(__file__).resolve().parent.parent / "data" / "runs"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "data" / "reports"


def _update_scan(scan_id: int, **fields) -> None:
    if not fields:
        return
    fields["updated_at"] = utc_now()
    assignments = ", ".join(f"{key} = ?" for key in fields)
    params = tuple(fields.values()) + (scan_id,)
    with get_conn() as conn:
        conn.execute(f"UPDATE scans SET {assignments} WHERE id = ?", params)


def _load_vulnerabilities(scan_id: int) -> list[dict]:
    return fetch_all("SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY id DESC", (scan_id,))


def _save_vulnerabilities(scan_id: int, vulnerabilities: list[dict]) -> None:
    records = []
    now = utc_now()
    for item in vulnerabilities:
        records.append(
            (
                scan_id,
                item["title"],
                item["severity"],
                item.get("score"),
                item.get("finding_kind", "vulnerability"),
                item.get("owasp_category"),
                item.get("confidence"),
                item.get("file"),
                item.get("line_number"),
                item["description"],
                item.get("evidence"),
                item["tool"],
                json.dumps(item.get("raw_json"), ensure_ascii=True),
                now,
            )
        )
    if records:
        execute_many(
            """
            INSERT INTO vulnerabilities (
                scan_id, title, severity, score, finding_kind, owasp_category, confidence,
                file, line_number, description, evidence, tool, raw_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            records,
        )


def _build_summary(vulnerabilities: list[dict], tool_status: dict, note: str | None = None) -> dict:
    real_findings = [item for item in vulnerabilities if item.get("finding_kind") == "vulnerability"]
    observations = [item for item in vulnerabilities if item.get("finding_kind") != "vulnerability"]
    counts = Counter(item["severity"] for item in real_findings if item["severity"] in {"low", "medium", "high", "critical"})
    owasp_counts = Counter(item.get("owasp_category") for item in real_findings if item.get("owasp_category"))
    summary = {
        "total_vulnerabilities": len(real_findings),
        "total_observations": len(observations),
        "severity_distribution": {
            "low": counts.get("low", 0),
            "medium": counts.get("medium", 0),
            "high": counts.get("high", 0),
            "critical": counts.get("critical", 0),
        },
        "owasp_top_10": dict(sorted(owasp_counts.items())),
        "tools": tool_status,
    }
    if note:
        summary["note"] = note
    return summary


def _finalize_reports(scan_id: int, summary: dict) -> None:
    scan = fetch_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    vulnerabilities = _load_vulnerabilities(scan_id)
    scan["summary"] = summary
    html_text = render_html_report(scan, vulnerabilities)
    html_path, pdf_path = write_reports(scan, vulnerabilities, html_text, REPORTS_DIR)
    _update_scan(scan_id, report_html_path=str(html_path), report_pdf_path=str(pdf_path))


def _set_running(scan_id: int, progress: int, tool_status: dict, stage: str) -> None:
    _update_scan(
        scan_id,
        status="running",
        progress=progress,
        current_stage=stage,
        tool_status=json.dumps(tool_status, ensure_ascii=True),
    )


def _run_sast(scan_id: int, target: str, source_type: str) -> None:
    workspace = RUNS_DIR / f"scan_{scan_id}"
    workspace.mkdir(parents=True, exist_ok=True)
    tool_status: dict = {}
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    vulnerabilities: list[dict] = []
    try:
        # 10% = repo cloned
        _update_scan(scan_id, progress=5, current_stage="Cloning repository")
        source_dir = prepare_source(workspace, source_type, target)
        _set_running(scan_id, 10, tool_status, "Repository cloned")
        
        source_stats = _scan_source_stats(source_dir)
        vulnerabilities.extend(build_sast_observations(source_stats))
        if source_stats.total_supported_files == 0:
            raise RuntimeError("No supported source files were found to scan in the uploaded source.")
            
        # 30% = semgrep started, 60% = semgrep running
        _set_running(scan_id, 30, tool_status, "Semgrep started")
        
        # We set it to 60% immediately after starting or right before call since it's the main task
        _set_running(scan_id, 60, tool_status, "Semgrep running")
        semgrep_findings, semgrep_tool, semgrep_stdout, semgrep_stderr = run_semgrep(source_dir)
        
        tool_status["semgrep"] = semgrep_tool
        stdout_chunks.append(f"=== semgrep stdout ===\n{semgrep_stdout}")
        stderr_chunks.append(f"=== semgrep stderr ===\n{semgrep_stderr}")
        
        bandit_findings: list[dict] = []
        if source_stats.python_files:
            _set_running(scan_id, 75, tool_status, "Running Bandit")
            bandit_findings, bandit_tool, bandit_stdout, bandit_stderr = run_bandit(source_dir)
            tool_status["bandit"] = bandit_tool
            stdout_chunks.append(f"=== bandit stdout ===\n{bandit_stdout}")
            stderr_chunks.append(f"=== bandit stderr ===\n{bandit_stderr}")
        else:
            tool_status["bandit"] = {"installed": True, "path": "python-only-skip", "skipped": True}
            
        # 90% = parsing results
        _set_running(scan_id, 90, tool_status, "Parsing results")
        vulnerabilities.extend(semgrep_findings + bandit_findings)
        _save_vulnerabilities(scan_id, vulnerabilities)
        real_findings = [item for item in vulnerabilities if item.get("finding_kind") == "vulnerability"]
        note = "Scan completed successfully with no verified SAST findings." if not real_findings else None
        summary = _build_summary(vulnerabilities, tool_status, note)
        _update_scan(
            scan_id,
            status="completed",
            progress=100,
            current_stage="Completed",
            tool_status=json.dumps(tool_status, ensure_ascii=True),
            summary_json=json.dumps(summary, ensure_ascii=True),
            stdout_log="\n\n".join(stdout_chunks),
            stderr_log="\n\n".join(stderr_chunks),
        )
        _finalize_reports(scan_id, summary)
    except Exception as exc:
        logger.exception("SAST scan %s failed", scan_id)
        if vulnerabilities:
            _save_vulnerabilities(scan_id, vulnerabilities)
        failure_summary = _build_summary(vulnerabilities, tool_status)
        _update_scan(
            scan_id,
            status="failed",
            progress=100,
            current_stage="Failed",
            tool_status=json.dumps(tool_status, ensure_ascii=True),
            summary_json=json.dumps(failure_summary, ensure_ascii=True),
            stdout_log="\n\n".join(stdout_chunks),
            stderr_log="\n\n".join(stderr_chunks),
            error_message=str(exc),
        )
        _finalize_reports(scan_id, failure_summary)


def _run_dast(scan_id: int, target: str, scan_mode: str) -> None:
    tool_status: dict = {}
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    try:
        _set_running(scan_id, 10, tool_status, "Baseline HTTP analysis")
        http_findings, http_stdout, http_stderr = run_http_baseline(target)
        http_limited = any(item.get("tool") == "http-baseline" and item.get("title", "").startswith("HTTP probe returned status") for item in http_findings)
        tool_status["http-baseline"] = {
            "installed": True,
            "path": "builtin",
            "mode": scan_mode,
            "status": "limited" if http_limited else "ok",
            "note": "Target returned non-2xx status; checks may be partial." if http_limited else None,
        }
        stdout_chunks.append(f"=== http-baseline stdout ===\n{http_stdout}")
        stderr_chunks.append(f"=== http-baseline stderr ===\n{http_stderr}")

        _set_running(scan_id, 35, tool_status, "Running Nmap")
        nmap_findings, nmap_tool, nmap_stdout, nmap_stderr = run_nmap(target, scan_mode)
        tool_status["nmap"] = nmap_tool
        stdout_chunks.append(f"=== nmap stdout ===\n{nmap_stdout}")
        stderr_chunks.append(f"=== nmap stderr ===\n{nmap_stderr}")

        _set_running(scan_id, 52, tool_status, "Running OWASP web checks")
        owasp_findings, owasp_stdout, owasp_stderr = run_owasp_web_checks(target, scan_mode)
        owasp_limited = any(item.get("tool") == "owasp-web" and item.get("title", "").startswith("OWASP checks ran on HTTP status") for item in owasp_findings)
        tool_status["owasp-web"] = {
            "installed": True,
            "path": "builtin",
            "mode": scan_mode,
            "status": "limited" if owasp_limited else "ok",
            "note": "Target returned non-2xx status; active checks were limited." if owasp_limited else None,
        }
        stdout_chunks.append(f"=== owasp-web stdout ===\n{owasp_stdout}")
        stderr_chunks.append(f"=== owasp-web stderr ===\n{owasp_stderr}")

        _set_running(scan_id, 68, tool_status, "Running Nuclei")
        nuclei_findings, nuclei_tool, nuclei_stdout, nuclei_stderr = run_nuclei(target, scan_mode)
        tool_status["nuclei"] = {**nuclei_tool, "status": "ok"}
        stdout_chunks.append(f"=== nuclei stdout ===\n{nuclei_stdout}")
        stderr_chunks.append(f"=== nuclei stderr ===\n{nuclei_stderr}")

        nikto_findings: list[dict] = []
        nikto_stdout = ""
        nikto_stderr = ""
        if scan_mode == "full":
            _set_running(scan_id, 84, tool_status, "Running Nikto")
            nikto_findings, nikto_tool, nikto_stdout, nikto_stderr = run_nikto(target, scan_mode)
            nikto_limited = any(item.get("tool") == "nikto" and item.get("finding_kind") == "observation" for item in nikto_findings)
            tool_status["nikto"] = {
                **nikto_tool,
                "status": "limited" if nikto_limited else "ok",
                "note": "Nikto completed with limited data or timeout." if nikto_limited else None,
            }
            stdout_chunks.append(f"=== nikto stdout ===\n{nikto_stdout}")
            stderr_chunks.append(f"=== nikto stderr ===\n{nikto_stderr}")
        else:
            tool_status["nikto"] = {"installed": False, "path": None, "mode": "quick-scan-skipped", "status": "skipped"}

        _set_running(scan_id, 94, tool_status, "Building report")
        vulnerabilities = enrich_with_owasp(http_findings + owasp_findings + nuclei_findings + nikto_findings + nmap_findings)
        _save_vulnerabilities(scan_id, vulnerabilities)
        real_findings = [item for item in vulnerabilities if item.get("finding_kind") == "vulnerability"]
        note = "Scan completed successfully with no verified DAST findings." if not real_findings else None
        summary = _build_summary(vulnerabilities, tool_status, note)
        _update_scan(
            scan_id,
            status="completed",
            progress=100,
            current_stage="Completed",
            tool_status=json.dumps(tool_status, ensure_ascii=True),
            summary_json=json.dumps(summary, ensure_ascii=True),
            stdout_log="\n\n".join(stdout_chunks),
            stderr_log="\n\n".join(stderr_chunks),
        )
        _finalize_reports(scan_id, summary)
    except Exception as exc:
        logger.exception("DAST scan %s failed", scan_id)
        _update_scan(
            scan_id,
            status="failed",
            progress=100,
            current_stage="Failed",
            tool_status=json.dumps(tool_status, ensure_ascii=True),
            stdout_log="\n\n".join(stdout_chunks),
            stderr_log="\n\n".join(stderr_chunks),
            error_message=str(exc),
        )


def create_scan(user_id: int, scan_type: str, target: str, source_type: str | None = None, scan_mode: str | None = None) -> int:
    now = utc_now()
    return execute(
        """
        INSERT INTO scans (
            user_id, scan_type, target, source_type, scan_mode, current_stage, status, progress, tool_status, summary_json,
            stdout_log, stderr_log, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'Queued', 'pending', 0, '{}', '{}', '', '', ?, ?)
        """,
        (user_id, scan_type, target, source_type, scan_mode, now, now),
    )


def launch_scan(scan_id: int) -> None:
    scan = fetch_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not scan:
        raise RuntimeError("Scan not found")
    if scan["scan_type"] == "sast":
        thread = threading.Thread(target=_run_sast, args=(scan_id, scan["target"], scan["source_type"] or "github"), daemon=True)
    else:
        thread = threading.Thread(target=_run_dast, args=(scan_id, scan["target"], scan.get("scan_mode") or "quick"), daemon=True)
    thread.start()

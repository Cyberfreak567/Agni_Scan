from __future__ import annotations

import json

from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import ValidationError

from ..db import fetch_all, fetch_one, get_conn
from ..models.schemas import DASTScanRequest, SASTScanRequest
from ..scanners.base import verify_tool
from ..scanners.dast import verify_nikto
from ..scanners.engine import RUNS_DIR, create_scan, launch_scan
from ..security import get_current_user, require_admin

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _row_to_scan(row: dict) -> dict:
    row["tool_status"] = json.loads(row.get("tool_status") or "{}")
    row["summary"] = json.loads(row.get("summary_json") or "{}")
    vulnerabilities = fetch_all("SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY id DESC", (row["id"],))
    for item in vulnerabilities:
        item["raw_json"] = json.loads(item["raw_json"]) if item.get("raw_json") else None
    row["vulnerabilities"] = vulnerabilities
    return row


@router.get("/tools")
def tool_status(user: dict = Depends(get_current_user)) -> dict:
    return {
        "semgrep": verify_tool("semgrep"),
        "bandit": verify_tool("bandit"),
        "owasp-web": {"installed": True, "path": "builtin", "mode": "active-http-checks"},
        "nuclei": verify_tool("nuclei"),
        "nmap": verify_tool("nmap"),
        "nikto": verify_nikto(),
    }


@router.post("/sast")
async def start_sast_scan(
    repo_url: str | None = Form(default=None),
    file: UploadFile | None = File(default=None),
    user: dict = Depends(get_current_user),
) -> dict:
    try:
        payload = SASTScanRequest(repo_url=repo_url) if repo_url else SASTScanRequest()
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.errors()) from exc
    if not payload.repo_url and not file:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provide either a GitHub URL or ZIP upload")
    if payload.repo_url and file:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Use either GitHub URL or ZIP upload, not both")
    if file and not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only ZIP archives are accepted")
    if file:
        uploads_dir = RUNS_DIR / "uploads"
        uploads_dir.mkdir(parents=True, exist_ok=True)
        archive_path = uploads_dir / Path(file.filename).name
        archive_path.write_bytes(await file.read())
        source_type = "zip"
        target = str(archive_path)
    else:
        source_type = "github"
        target = str(payload.repo_url)
    scan_id = create_scan(user["id"], "sast", target, source_type=source_type)
    launch_scan(scan_id)
    return {"scan_id": scan_id, "status": "pending"}


@router.post("/dast")
def start_dast_scan(payload: DASTScanRequest, user: dict = Depends(get_current_user)) -> dict:
    scan_id = create_scan(user["id"], "dast", str(payload.target_url), scan_mode=payload.mode)
    launch_scan(scan_id)
    return {"scan_id": scan_id, "status": "pending", "mode": payload.mode}


@router.get("")
def list_scans(user: dict = Depends(get_current_user)) -> list[dict]:
    if user["role"] == "admin":
        scans = fetch_all("SELECT * FROM scans ORDER BY id DESC")
    else:
        scans = fetch_all("SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC", (user["id"],))
    return [_row_to_scan(row) for row in scans]


@router.get("/admin/summary")
def admin_summary(user: dict = Depends(require_admin)) -> dict:
    scans = fetch_all("SELECT * FROM scans ORDER BY id DESC")
    vulnerabilities = fetch_all("SELECT severity FROM vulnerabilities WHERE finding_kind = 'vulnerability'")
    distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for item in vulnerabilities:
        severity = item["severity"]
        distribution[severity] = distribution.get(severity, 0) + 1
    return {
        "total_scans": len(scans),
        "completed_scans": len([scan for scan in scans if scan["status"] == "completed"]),
        "failed_scans": len([scan for scan in scans if scan["status"] == "failed"]),
        "total_vulnerabilities": len(vulnerabilities),
        "severity_distribution": distribution,
    }


@router.get("/{scan_id}")
def get_scan(scan_id: int, user: dict = Depends(get_current_user)) -> dict:
    scan = fetch_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return _row_to_scan(scan)


@router.delete("/{scan_id}")
def delete_scan(scan_id: int, user: dict = Depends(get_current_user)) -> dict:
    scan = fetch_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    for report_key in ("report_html_path", "report_pdf_path"):
        report_path = scan.get(report_key)
        if report_path:
            path_obj = Path(report_path)
            if path_obj.exists():
                path_obj.unlink(missing_ok=True)

    with get_conn() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    return {"ok": True, "deleted_scan_id": scan_id}

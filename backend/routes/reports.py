from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse

from ..db import fetch_all, fetch_one
from ..security import get_current_user

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _check_scan_access(scan_id: int, user: dict) -> dict:
    scan = fetch_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if user["role"] != "admin" and scan["user_id"] != user["id"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return scan


@router.get("/{scan_id}/json")
def download_json(scan_id: int, user: dict = Depends(get_current_user)) -> JSONResponse:
    scan = _check_scan_access(scan_id, user)
    vulnerabilities = fetch_all("SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY id DESC", (scan_id,))
    scan["tool_status"] = json.loads(scan.get("tool_status") or "{}")
    scan["summary"] = json.loads(scan.get("summary_json") or "{}")
    for item in vulnerabilities:
        item["raw_json"] = json.loads(item["raw_json"]) if item.get("raw_json") else None
    return JSONResponse({"scan": scan, "vulnerabilities": vulnerabilities})


@router.get("/{scan_id}/html")
def download_html(scan_id: int, user: dict = Depends(get_current_user)) -> FileResponse:
    scan = _check_scan_access(scan_id, user)
    if not scan.get("report_html_path"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="HTML report not available yet")
    return FileResponse(scan["report_html_path"], media_type="text/html", filename=f"scan_{scan_id}.html")


@router.get("/{scan_id}/pdf")
def download_pdf(scan_id: int, user: dict = Depends(get_current_user)) -> FileResponse:
    scan = _check_scan_access(scan_id, user)
    if not scan.get("report_pdf_path"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PDF report not available yet")
    return FileResponse(scan["report_pdf_path"], media_type="application/pdf", filename=f"scan_{scan_id}.pdf")

from __future__ import annotations

from typing import Any


SEVERITY_ORDER = {
    "info": "low",
    "warning": "medium",
    "error": "high",
    "critical": "critical",
    "low": "low",
    "medium": "medium",
    "high": "high",
}


def normalize_severity(value: str | None) -> str:
    if not value:
        return "medium"
    return SEVERITY_ORDER.get(value.lower(), "medium")


def parse_semgrep_output(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(payload, dict):
        return findings

    for item in payload.get("results", []):
        extra = item.get("extra", {})
        # Extract required fields: file path, line number, rule id, severity, message
        findings.append(
            {
                "title": item.get("check_id", "Semgrep finding"),
                "severity": normalize_severity(extra.get("severity")),
                "file": item.get("path"),
                "line_number": (item.get("start") or {}).get("line"),
                "description": extra.get("message") or "Semgrep detected a potentially insecure pattern.",
                "tool": "semgrep",
                "finding_kind": "vulnerability",
                "confidence": extra.get("metadata", {}).get("confidence"),
                "raw_json": item,
            }
        )
    return findings


def parse_bandit_output(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in payload.get("results", []):
        findings.append(
            {
                "title": item.get("test_name") or item.get("test_id") or "Bandit finding",
                "severity": normalize_severity(item.get("issue_severity")),
                "file": item.get("filename"),
                "line_number": item.get("line_number"),
                "description": item.get("issue_text") or "Bandit identified a potential Python security issue.",
                "tool": "bandit",
                "raw_json": item,
            }
        )
    return findings

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any


OWASP_RULES = [
    ("sql", "A03:2021 - Injection"),
    ("xss", "A03:2021 - Injection"),
    ("ssti", "A03:2021 - Injection"),
    ("rce", "A03:2021 - Injection"),
    ("lfi", "A01:2021 - Broken Access Control"),
    ("redirect", "A01:2021 - Broken Access Control"),
    ("auth", "A07:2021 - Identification and Authentication Failures"),
    ("default-login", "A07:2021 - Identification and Authentication Failures"),
    ("cookie", "A07:2021 - Identification and Authentication Failures"),
    ("header", "A05:2021 - Security Misconfiguration"),
    ("misconfig", "A05:2021 - Security Misconfiguration"),
    ("exposure", "A02:2021 - Cryptographic Failures"),
    ("tls", "A02:2021 - Cryptographic Failures"),
    ("server", "A05:2021 - Security Misconfiguration"),
]

SEVERITY_SCORES = {
    "info": 0.0,
    "low": 3.1,
    "medium": 5.3,
    "high": 8.1,
    "critical": 9.5,
}


def infer_owasp(*values: str | None) -> str:
    haystack = " ".join(value or "" for value in values).lower()
    for token, category in OWASP_RULES:
        if token in haystack:
            return category
    return "A05:2021 - Security Misconfiguration"


def severity_from_nuclei(item: dict[str, Any]) -> str:
    severity = (((item.get("info") or {}).get("severity")) or "medium").lower()
    if severity == "info":
        return "low"
    if severity not in {"low", "medium", "high", "critical"}:
        return "medium"
    return severity


def score_from_severity(severity: str) -> float:
    return SEVERITY_SCORES.get(severity, 5.0)


def score_from_nuclei(item: dict[str, Any]) -> float:
    classification = ((item.get("info") or {}).get("classification")) or {}
    raw_score = classification.get("cvss-score") or classification.get("cvss_score")
    if raw_score is not None:
        try:
            return float(raw_score)
        except (TypeError, ValueError):
            pass
    return score_from_severity(severity_from_nuclei(item))


def parse_nuclei_output(stdout: str) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        info = item.get("info") or {}
        tags = ",".join(info.get("tags") or [])
        template_id = item.get("template-id") or "unknown-template"
        location = item.get("matched-at") or item.get("url") or "unknown-target"
        key = (template_id, location)
        evidence = item.get("matcher-name") or item.get("matched-at") or item.get("curl-command")

        if key not in grouped:
            grouped[key] = {
                "title": info.get("name") or template_id or "Nuclei finding",
                "severity": severity_from_nuclei(item),
                "score": score_from_nuclei(item),
                "finding_kind": "vulnerability",
                "owasp_category": infer_owasp(tags, info.get("name"), info.get("description"), template_id),
                "confidence": "high",
                "file": location,
                "line_number": None,
                "description": info.get("description") or f"Nuclei matched template {template_id}.",
                "tool": "nuclei",
                "raw_json": [],
                "_evidence": [],
            }

        grouped[key]["raw_json"].append(item)
        if evidence and evidence not in grouped[key]["_evidence"]:
            grouped[key]["_evidence"].append(evidence)

    findings: list[dict[str, Any]] = []
    for entry in grouped.values():
        evidence_items = entry.pop("_evidence")
        entry["evidence"] = ", ".join(evidence_items[:10]) if evidence_items else entry["file"]
        findings.append(entry)
    return findings


def parse_nmap_output(xml_text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not xml_text.strip():
        return findings
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        address = host.find("address")
        host_addr = address.attrib.get("addr") if address is not None else "unknown-host"
        open_ports = 0
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            if state is None or state.attrib.get("state") != "open":
                continue
            open_ports += 1
            port_id = port.attrib.get("portid")
            service_name = service.attrib.get("name") if service is not None else "unknown-service"
            findings.append(
                {
                    "title": f"Open port {port_id}/{service_name}",
                    "severity": "info",
                    "score": 0.0,
                    "finding_kind": "observation",
                    "owasp_category": None,
                    "confidence": "high",
                    "file": host_addr,
                    "line_number": None,
                    "description": f"Nmap observed host {host_addr} exposing port {port_id} ({service_name}).",
                    "evidence": f"{host_addr}:{port_id}",
                    "tool": "nmap",
                    "raw_json": {"host": host_addr, "port": port_id, "service": service_name},
                }
            )
        if open_ports == 0:
            findings.append(
                {
                    "title": "No open ports detected in scanned range",
                    "severity": "info",
                    "score": 0.0,
                    "finding_kind": "observation",
                    "owasp_category": None,
                    "confidence": "high",
                    "file": host_addr,
                    "line_number": None,
                    "description": f"Nmap reached host {host_addr} but did not observe open ports in the selected scan range.",
                    "evidence": host_addr,
                    "tool": "nmap",
                    "raw_json": {"host": host_addr, "open_ports": 0},
                }
            )
    return findings


def parse_nikto_output(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    records = payload if isinstance(payload, list) else [payload]
    for record in records:
        if not isinstance(record, dict):
            continue
        item_list = record.get("vulnerabilities") or record.get("items") or []
        host = record.get("host")
        port = record.get("port")
        for item in item_list:
            message = item.get("msg") or item.get("message") or "Nikto identified a web exposure."
            if "unable to connect" in message.lower():
                continue
            uri = item.get("url") or item.get("uri") or host
            if uri and host and isinstance(uri, str) and uri.startswith("/"):
                uri = f"http://{host}:{port}{uri}" if port else f"http://{host}{uri}"
            findings.append(
                {
                    "title": item.get("id") or "Nikto finding",
                    "severity": "medium",
                    "score": 5.0,
                    "finding_kind": "vulnerability",
                    "owasp_category": infer_owasp(message, uri),
                    "confidence": "low",
                    "file": uri,
                    "line_number": None,
                    "description": message,
                    "evidence": item.get("method") or uri,
                    "tool": "nikto",
                    "raw_json": item,
                }
            )
    return findings


def parse_nikto_text(raw_text: str, target: str | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not raw_text:
        return findings
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line.startswith("+"):
            continue
        message = line.lstrip("+").strip()
        if not message or message.lower().startswith(("target ip", "target hostname", "start time", "end time")):
            continue
        severity = "low"
        lowered = message.lower()
        if any(token in lowered for token in ("xss", "sql", "injection", "rce", "command execution", "shell")):
            severity = "high"
        elif any(token in lowered for token in ("directory listing", "admin", "login", "password", "exposed", "header")):
            severity = "medium"
        findings.append(
            {
                "title": "Nikto finding",
                "severity": severity,
                "score": score_from_severity(severity),
                "finding_kind": "vulnerability",
                "owasp_category": infer_owasp(message, target or ""),
                "confidence": "low",
                "file": target or "",
                "line_number": None,
                "description": message,
                "evidence": message[:500],
                "tool": "nikto",
                "raw_json": {"line": message},
            }
        )
    return findings

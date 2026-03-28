from __future__ import annotations

import html
from pathlib import Path


def _group_findings(vulnerabilities: list[dict]) -> tuple[list[dict], list[dict]]:
    real_findings = [item for item in vulnerabilities if item.get("finding_kind") == "vulnerability"]
    observations = [item for item in vulnerabilities if item.get("finding_kind") != "vulnerability"]
    return real_findings, observations


def _finding_rows(items: list[dict], empty_text: str) -> str:
    if not items:
        return f"<tr><td colspan='10'>{html.escape(empty_text)}</td></tr>"
    rows = []
    for item in items:
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['tool'])}</td>"
            f"<td>{html.escape(item['severity'])}</td>"
            f"<td>{html.escape(str(item.get('score') if item.get('score') is not None else '-'))}</td>"
            f"<td>{html.escape(item.get('confidence') or '-')}</td>"
            f"<td>{html.escape(item.get('owasp_category') or '-')}</td>"
            f"<td>{html.escape(item['title'])}</td>"
            f"<td>{html.escape(item.get('file') or '-')}</td>"
            f"<td>{html.escape(str(item.get('line_number') or '-'))}</td>"
            f"<td>{html.escape(item['description'])}</td>"
            f"<td>{html.escape(item.get('evidence') or '-')}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _summary_cards(scan: dict) -> str:
    summary = scan["summary"]
    cards = [
        ("Verified Vulnerabilities", str(summary.get("total_vulnerabilities", 0))),
        ("Observations", str(summary.get("total_observations", 0))),
        ("High + Critical", str((summary.get("severity_distribution") or {}).get("high", 0) + (summary.get("severity_distribution") or {}).get("critical", 0))),
        ("Current Stage", scan.get("current_stage") or "-"),
    ]
    return "\n".join(
        "<div class='card'>"
        f"<div class='label'>{html.escape(label)}</div>"
        f"<div class='metric'>{html.escape(value)}</div>"
        "</div>"
        for label, value in cards
    )


def _kv_table(title: str, payload: dict[str, object], empty_text: str) -> str:
    if not payload:
        return f"<div class='card'><div class='label'>{html.escape(title)}</div><div>{html.escape(empty_text)}</div></div>"
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(key))}</td>"
        f"<td>{html.escape(str(value))}</td>"
        "</tr>"
        for key, value in payload.items()
    )
    return (
        f"<div class='section'>"
        f"<h2>{html.escape(title)}</h2>"
        "<table><thead><tr><th>Category</th><th>Count</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "</div>"
    )


def render_html_report(scan: dict, vulnerabilities: list[dict]) -> str:
    findings, observations = _group_findings(vulnerabilities)
    findings_rows = _finding_rows(findings, "No verified vulnerabilities were detected in this scan.")
    observation_rows = _finding_rows(observations, "No additional observations were captured.")
    severity_table = _kv_table(
        "Severity Distribution",
        scan["summary"].get("severity_distribution") or {},
        "No severity data recorded.",
    )
    owasp_table = _kv_table(
        "OWASP Top 10 Mapping",
        scan["summary"].get("owasp_top_10") or {},
        "No OWASP mapping generated.",
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Scan Report #{scan['id']}</title>
  <style>
    :root {{
      --bg: #f3efe6;
      --panel: #fffdf8;
      --ink: #1f2933;
      --muted: #5b6470;
      --border: #d9d0c4;
      --accent: #9a3b3b;
    }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background: linear-gradient(140deg, #f4ebdb, #fbf8f3);
      color: var(--ink);
    }}
    .wrap {{
      max-width: 1200px;
      margin: 32px auto;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 28px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.08);
    }}
    h1, h2 {{ margin-top: 0; }}
    .meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }}
    .card {{
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px;
      background: #fff;
    }}
    .metric {{
      font-size: 28px;
      font-weight: 700;
    }}
    .label {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 6px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 14px;
      table-layout: fixed;
    }}
    th, td {{
      border: 1px solid var(--border);
      padding: 10px;
      text-align: left;
      vertical-align: top;
      font-size: 13px;
      word-break: break-word;
    }}
    th {{ background: #f7f1e7; }}
    pre {{
      white-space: pre-wrap;
      background: #f7f1e7;
      border-radius: 14px;
      padding: 16px;
      border: 1px solid var(--border);
    }}
    .section {{
      margin-top: 26px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Red Teaming Scan Report</h1>
    <div class="meta">
      <div class="card"><div class="label">Scan ID</div><div>#{scan['id']}</div></div>
      <div class="card"><div class="label">Type</div><div>{html.escape(scan['scan_type'].upper())}</div></div>
      <div class="card"><div class="label">Mode</div><div>{html.escape((scan.get('scan_mode') or '-').upper())}</div></div>
      <div class="card"><div class="label">Status</div><div>{html.escape(scan['status'])}</div></div>
      <div class="card"><div class="label">Target</div><div>{html.escape(scan['target'])}</div></div>
      <div class="card"><div class="label">Stage</div><div>{html.escape(scan.get('current_stage') or '-')}</div></div>
    </div>

    <div class="section">
      <h2>Executive Summary</h2>
      <div class="meta">
        {_summary_cards(scan)}
      </div>
    </div>

    {severity_table}
    {owasp_table}

    <div class="section">
      <h2>Verified Vulnerabilities</h2>
      <table>
        <thead>
          <tr>
            <th>Tool</th><th>Severity</th><th>Score</th><th>Confidence</th><th>OWASP</th><th>Title</th><th>Location</th><th>Line</th><th>Description</th><th>Evidence</th>
          </tr>
        </thead>
        <tbody>{findings_rows}</tbody>
      </table>
    </div>

    <div class="section">
      <h2>Observations</h2>
      <table>
        <thead>
          <tr>
            <th>Tool</th><th>Severity</th><th>Score</th><th>Confidence</th><th>OWASP</th><th>Title</th><th>Location</th><th>Line</th><th>Description</th><th>Evidence</th>
          </tr>
        </thead>
        <tbody>{observation_rows}</tbody>
      </table>
    </div>
  </div>
</body>
</html>"""


def render_pdf_bytes(scan: dict, vulnerabilities: list[dict]) -> bytes:
    findings, observations = _group_findings(vulnerabilities)
    lines = [
        "Red Teaming Scan Report",
        f"Scan ID: {scan['id']}",
        f"Type: {scan['scan_type'].upper()}",
        f"Mode: {(scan.get('scan_mode') or '-').upper()}",
        f"Status: {scan['status']}",
        f"Target: {scan['target']}",
        "",
        "Executive Summary",
    ]
    summary = scan["summary"]
    lines.extend(
        [
            f"Verified vulnerabilities: {summary.get('total_vulnerabilities', 0)}",
            f"Observations: {summary.get('total_observations', 0)}",
        ]
    )
    for severity, count in (summary.get("severity_distribution") or {}).items():
        lines.append(f"{severity.title()}: {count}")
    if summary.get("owasp_top_10"):
        lines.append("")
        lines.append("OWASP Mapping")
        for key, value in summary["owasp_top_10"].items():
            lines.append(f"{key}: {value}")

    lines.append("")
    lines.append("Verified Vulnerabilities")
    if findings:
        for item in findings[:40]:
            lines.extend(
                [
                    f"- {item['severity'].upper()} | {item['title']}",
                    f"  Tool: {item['tool']}",
                    f"  Score: {item.get('score') if item.get('score') is not None else '-'}",
                    f"  Confidence: {item.get('confidence') or '-'}",
                    f"  OWASP: {item.get('owasp_category') or '-'}",
                    f"  Location: {item.get('file') or '-'}",
                    f"  Evidence: {item.get('evidence') or '-'}",
                    f"  Description: {item['description']}",
                ]
            )
    else:
        lines.append("- No verified vulnerabilities detected.")

    lines.append("")
    lines.append("Observations")
    if observations:
        for item in observations[:25]:
            lines.extend(
                [
                    f"- {item['title']}",
                    f"  Tool: {item['tool']}",
                    f"  Score: {item.get('score') if item.get('score') is not None else '-'}",
                    f"  Confidence: {item.get('confidence') or '-'}",
                    f"  Location: {item.get('file') or '-'}",
                    f"  Evidence: {item.get('evidence') or '-'}",
                ]
            )
    else:
        lines.append("- No additional observations captured.")

    wrapped: list[str] = []
    for line in lines:
        while len(line) > 100:
            wrapped.append(line[:100])
            line = line[100:]
        wrapped.append(line)

    content_lines = ["BT", "/F1 10 Tf", "40 790 Td"]
    for index, line in enumerate(wrapped[:220]):
        if index:
            content_lines.append("0 -13 Td")
        escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content_lines.append(f"({escaped}) Tj")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = [
        b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n",
        b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n",
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>endobj\n",
        b"4 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n",
        f"5 0 obj<< /Length {len(stream)} >>stream\n".encode("ascii") + stream + b"\nendstream endobj\n",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(output))
        output.extend(obj)
    xref_pos = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode("ascii"))
    return bytes(output)


def write_reports(scan: dict, vulnerabilities: list[dict], html_text: str, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = output_dir / f"scan_{scan['id']}.html"
    pdf_path = output_dir / f"scan_{scan['id']}.pdf"
    html_path.write_text(html_text, encoding="utf-8")
    pdf_path.write_bytes(render_pdf_bytes(scan, vulnerabilities))
    return html_path, pdf_path

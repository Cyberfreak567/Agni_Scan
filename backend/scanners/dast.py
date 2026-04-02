from __future__ import annotations

import json
import re
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from ..parsers.dast import infer_owasp, parse_nikto_output, parse_nmap_output, parse_nuclei_output, score_from_severity
from .base import build_tool_command, resolve_tool, run_command, verify_tool

CUSTOM_NUCLEI_TEMPLATES = Path(__file__).resolve().parent / "nuclei_templates"
OFFICIAL_NUCLEI_TEMPLATES = Path(__file__).resolve().parent.parent / "data" / "tools" / "nuclei-templates"
NUCLEI_APPDATA = Path(__file__).resolve().parent.parent / "data" / "tools" / "nuclei-home"
DOCKER_CONFIG = Path(__file__).resolve().parent.parent / "data" / "tools" / "docker-config"
SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql.*error",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"postgresql.*error",
    r"sqlite.*error",
    r"odbc.*sql",
]


class _HTMLSignalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()
        if tag == "a" and attr_map.get("href"):
            self.links.append(attr_map["href"])
        elif tag == "form":
            self._current_form = {
                "action": attr_map.get("action", ""),
                "method": (attr_map.get("method") or "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": attr_map.get("name", ""),
                    "type": (attr_map.get("type") or "text").lower(),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


def _http_fetch(target_url: str, timeout: int = 20) -> tuple[str, object, int]:
    request = Request(target_url, headers={"User-Agent": "RedTeamScanner/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(250_000).decode("utf-8", errors="replace")
            return body, response.headers, response.status
    except HTTPError as exc:
        body = exc.read(250_000).decode("utf-8", errors="replace")
        return body, exc.headers, exc.code


def _same_origin(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    current = urlparse(candidate)
    return base.scheme == current.scheme and base.hostname == current.hostname and (base.port or None) == (current.port or None)


def _collect_candidate_urls(target_url: str, body: str, mode: str) -> tuple[list[str], list[dict]]:
    parser = _HTMLSignalParser()
    parser.feed(body)
    candidates = {target_url}
    for href in parser.links[:20]:
        absolute = urljoin(target_url, href)
        if _same_origin(target_url, absolute):
            candidates.add(absolute)
    if mode == "full":
        expanded: set[str] = set(candidates)
        for url in list(candidates):
            if len(expanded) >= 30:
                break
            try:
                linked_body, _, _ = _http_fetch(url, timeout=12)
            except Exception:
                continue
            nested_parser = _HTMLSignalParser()
            nested_parser.feed(linked_body)
            for href in nested_parser.links[:10]:
                absolute = urljoin(url, href)
                if _same_origin(target_url, absolute):
                    expanded.add(absolute)
        candidates = expanded
    return sorted(candidates), parser.forms


def _extract_host(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("Target URL must be a valid HTTP or HTTPS URL")
    return parsed.hostname


def _nikto_target(target_url: str) -> str:
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    if hostname not in {"127.0.0.1", "localhost"}:
        return target_url
    replacement = "host.docker.internal"
    netloc = replacement
    if parsed.port:
        netloc = f"{replacement}:{parsed.port}"
    return parsed._replace(netloc=netloc).geturl()


def verify_nikto() -> dict:
    docker_path = resolve_tool("docker")
    return {
        "installed": bool(docker_path),
        "path": docker_path,
        "mode": "docker-container" if docker_path else "unavailable",
    }


def run_http_baseline(target_url: str) -> tuple[list[dict], str, str]:
    try:
        body, headers, status = _http_fetch(target_url)
    except Exception as exc:
        return [], "", f"HTTP baseline probe skipped: {exc}"

    findings: list[dict] = []
    if status >= 400:
        findings.append(
            {
                "title": f"HTTP probe returned status {status}",
                "severity": "low",
                "score": 0.0,
                "finding_kind": "observation",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "confidence": "high",
                "file": target_url,
                "line_number": None,
                "description": f"Initial HTTP baseline request received status {status}. Results may be partial for blocked or missing pages.",
                "evidence": f"HTTP status: {status}",
                "tool": "http-baseline",
                "raw_json": {"url": target_url, "status": status},
            }
        )

    if target_url.startswith("http://"):
        findings.append(
            {
                "title": "Application served without HTTPS",
                "severity": "high",
                "score": score_from_severity("high"),
                "finding_kind": "vulnerability",
                "owasp_category": "A02:2021 - Cryptographic Failures",
                "confidence": "high",
                "file": target_url,
                "line_number": None,
                "description": "The target is served over plain HTTP, which exposes user sessions and credentials to interception.",
                "evidence": target_url,
                "tool": "http-baseline",
                "raw_json": {"url": target_url, "status": status},
            }
        )

    expected_headers = {
        "Content-Security-Policy": ("Missing Content-Security-Policy", "medium"),
        "X-Frame-Options": ("Missing X-Frame-Options", "medium"),
        "X-Content-Type-Options": ("Missing X-Content-Type-Options", "low"),
        "Referrer-Policy": ("Missing Referrer-Policy", "low"),
    }
    for header, (title, severity) in expected_headers.items():
        if not headers.get(header):
            findings.append(
                {
                    "title": title,
                    "severity": severity,
                    "score": score_from_severity(severity),
                    "finding_kind": "vulnerability",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "confidence": "high",
                    "file": target_url,
                    "line_number": None,
                    "description": f"The HTTP response does not include the {header} header.",
                    "evidence": f"Missing header: {header}",
                    "tool": "http-baseline",
                    "raw_json": {"missing_header": header, "url": target_url},
                }
            )

    for disclosure_header in ("Server", "X-Powered-By"):
        value = headers.get(disclosure_header)
        if value:
            findings.append(
                {
                    "title": f"{disclosure_header} header discloses technology",
                    "severity": "low",
                    "score": 0.0,
                    "finding_kind": "observation",
                    "owasp_category": "A05:2021 - Security Misconfiguration",
                    "confidence": "high",
                    "file": target_url,
                    "line_number": None,
                    "description": f"The response exposes {disclosure_header}: {value}.",
                    "evidence": f"{disclosure_header}: {value}",
                    "tool": "http-baseline",
                    "raw_json": {"header": disclosure_header, "value": value},
                }
            )

    set_cookie_headers = headers.get_all("Set-Cookie", [])
    for cookie in set_cookie_headers:
        cookie_lower = cookie.lower()
        if "httponly" not in cookie_lower:
            findings.append(
                {
                    "title": "Cookie missing HttpOnly flag",
                    "severity": "medium",
                    "score": score_from_severity("medium"),
                    "finding_kind": "vulnerability",
                    "owasp_category": "A07:2021 - Identification and Authentication Failures",
                    "confidence": "medium",
                    "file": target_url,
                    "line_number": None,
                    "description": "A cookie set by the application does not include the HttpOnly attribute.",
                    "evidence": cookie,
                    "tool": "http-baseline",
                    "raw_json": {"cookie": cookie},
                }
            )
        if target_url.startswith("https://") and "secure" not in cookie_lower:
            findings.append(
                {
                    "title": "Cookie missing Secure flag",
                    "severity": "medium",
                    "score": score_from_severity("medium"),
                    "finding_kind": "vulnerability",
                    "owasp_category": "A02:2021 - Cryptographic Failures",
                    "confidence": "medium",
                    "file": target_url,
                    "line_number": None,
                    "description": "A cookie set by the application does not include the Secure attribute on HTTPS.",
                    "evidence": cookie,
                    "tool": "http-baseline",
                    "raw_json": {"cookie": cookie},
                }
            )

    if target_url.startswith("http://") and re.search(r'type\s*=\s*["\']password["\']', body, flags=re.IGNORECASE):
        findings.append(
            {
                "title": "Password form submitted over HTTP",
                "severity": "high",
                "score": score_from_severity("high"),
                "finding_kind": "vulnerability",
                "owasp_category": "A02:2021 - Cryptographic Failures",
                "confidence": "high",
                "file": target_url,
                "line_number": None,
                "description": "The page contains a password field while the site is served over HTTP.",
                "evidence": "Password input detected in non-TLS page source",
                "tool": "http-baseline",
                "raw_json": {"url": target_url},
            }
        )

    return findings, f"Fetched {target_url} (status {status}) and inspected headers/body.", ""


def run_owasp_web_checks(target_url: str, mode: str) -> tuple[list[dict], str, str]:
    try:
        body, headers, status = _http_fetch(target_url)
    except Exception as exc:
        return [], "", f"OWASP web checks skipped: {exc}"

    findings: list[dict] = []
    if status >= 400:
        findings.append(
            {
                "title": f"OWASP checks ran on HTTP status {status}",
                "severity": "low",
                "score": 0.0,
                "finding_kind": "observation",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "confidence": "high",
                "file": target_url,
                "line_number": None,
                "description": f"Target responded with HTTP {status}. Active OWASP checks were limited to available content.",
                "evidence": f"HTTP status: {status}",
                "tool": "owasp-web",
                "raw_json": {"url": target_url, "status": status},
            }
        )

    candidate_urls, forms = _collect_candidate_urls(target_url, body, mode)

    if headers.get("Access-Control-Allow-Origin") == "*" and str(headers.get("Access-Control-Allow-Credentials", "")).lower() == "true":
        findings.append(
            {
                "title": "Permissive CORS with credentials",
                "severity": "high",
                "score": score_from_severity("high"),
                "finding_kind": "vulnerability",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "confidence": "high",
                "file": target_url,
                "line_number": None,
                "description": "The application allows cross-origin requests from any origin while also allowing credentials.",
                "evidence": "Access-Control-Allow-Origin: * with credentials enabled",
                "tool": "owasp-web",
                "raw_json": {"url": target_url},
            }
        )

    if re.search(r"<title>\s*Index of /", body, flags=re.IGNORECASE) or "Parent Directory" in body:
        findings.append(
            {
                "title": "Directory listing exposed",
                "severity": "medium",
                "score": score_from_severity("medium"),
                "finding_kind": "vulnerability",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "confidence": "high",
                "file": target_url,
                "line_number": None,
                "description": "The application appears to expose a directory index to unauthenticated users.",
                "evidence": "Directory listing markers detected in response body",
                "tool": "owasp-web",
                "raw_json": {"url": target_url},
            }
        )

    for form in forms:
        if form["method"] == "post":
            hidden_names = {item["name"].lower() for item in form["inputs"] if item["type"] == "hidden"}
            if not any(token in name for name in hidden_names for token in ("csrf", "xsrf", "token")):
                findings.append(
                    {
                        "title": "POST form without visible CSRF token",
                        "severity": "medium",
                        "score": score_from_severity("medium"),
                        "finding_kind": "vulnerability",
                        "owasp_category": "A01:2021 - Broken Access Control",
                        "confidence": "medium",
                        "file": urljoin(target_url, form.get("action") or ""),
                        "line_number": None,
                        "description": "A discovered POST form does not include a hidden field that looks like a CSRF token.",
                        "evidence": f"Form action: {form.get('action') or '/'}",
                        "tool": "owasp-web",
                        "raw_json": form,
                    }
                )

    if mode == "full":
        reflection_marker = "RTSREFLECT123"
        sql_marker = "RTSSQL123'"
        for candidate in candidate_urls[:20]:
            parsed = urlparse(candidate)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if not params:
                continue
            reflected = False
            sql_error = False
            for index, (key, _value) in enumerate(params):
                mutated = list(params)
                mutated[index] = (key, reflection_marker)
                reflect_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                try:
                    reflect_body, _, _ = _http_fetch(reflect_url, timeout=12)
                except Exception:
                    continue
                if reflection_marker in reflect_body:
                    reflected = True

                mutated[index] = (key, sql_marker)
                sql_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                try:
                    sql_body, _, _ = _http_fetch(sql_url, timeout=12)
                except Exception:
                    continue
                if any(re.search(pattern, sql_body, flags=re.IGNORECASE) for pattern in SQL_ERROR_PATTERNS):
                    sql_error = True

            if reflected:
                findings.append(
                    {
                        "title": "Reflected input detected in parameter response",
                        "severity": "medium",
                        "score": score_from_severity("medium"),
                        "finding_kind": "vulnerability",
                        "owasp_category": "A03:2021 - Injection",
                        "confidence": "medium",
                        "file": candidate,
                        "line_number": None,
                        "description": "A benign marker injected into a GET parameter was reflected in the server response without sanitization.",
                        "evidence": reflection_marker,
                        "tool": "owasp-web",
                        "raw_json": {"url": candidate},
                    }
                )
            if sql_error:
                findings.append(
                    {
                        "title": "SQL error behavior triggered by parameter mutation",
                        "severity": "high",
                        "score": score_from_severity("high"),
                        "finding_kind": "vulnerability",
                        "owasp_category": "A03:2021 - Injection",
                        "confidence": "medium",
                        "file": candidate,
                        "line_number": None,
                        "description": "A quote-based test payload caused database-style error text in the response, suggesting injectable server-side query handling.",
                        "evidence": sql_marker,
                        "tool": "owasp-web",
                        "raw_json": {"url": candidate},
                    }
                )

    return findings, f"Collected {len(candidate_urls)} same-origin URLs and ran OWASP-oriented web checks (base status {status}).", ""


def run_nuclei(target_url: str, mode: str) -> tuple[list[dict], dict, str, str]:
    tool_state = verify_tool("nuclei")
    if not tool_state["installed"]:
        raise RuntimeError("nuclei is not installed or not accessible on PATH")

    NUCLEI_APPDATA.mkdir(parents=True, exist_ok=True)
    template_args = ["-t", str(CUSTOM_NUCLEI_TEMPLATES)]
    if OFFICIAL_NUCLEI_TEMPLATES.exists():
        template_args.extend(["-t", str(OFFICIAL_NUCLEI_TEMPLATES / "http" / "misconfiguration")])
        template_args.extend(["-t", str(OFFICIAL_NUCLEI_TEMPLATES / "http" / "exposures")])
        if mode == "full":
            template_args.extend(["-t", str(OFFICIAL_NUCLEI_TEMPLATES / "http" / "default-logins")])
            template_args.extend(["-t", str(OFFICIAL_NUCLEI_TEMPLATES / "http" / "vulnerabilities")])
            template_args.extend(["-t", str(OFFICIAL_NUCLEI_TEMPLATES / "dast" / "vulnerabilities")])
            template_args.extend(["-t", str(OFFICIAL_NUCLEI_TEMPLATES / "http" / "technologies")])
    extra_args = ["-as"] if mode == "full" else ["-duc"]

    command = build_tool_command(
        "nuclei",
        "-u",
        target_url,
        *template_args,
        *extra_args,
        "-j",
        "-silent",
        "-ni",
        "-timeout",
        "12",
        "-retries",
        "2",
        "-rate-limit",
        "120",
        "-concurrency",
        "30",
    )
    result = run_command(command, env={"APPDATA": str(NUCLEI_APPDATA)})
    if result.returncode not in {0, 1}:
        raise RuntimeError(f"Nuclei failed: {result.stderr or result.stdout}")
    findings = parse_nuclei_output(result.stdout)
    return findings, tool_state, result.stdout, result.stderr


def run_nmap(target_url: str, mode: str) -> tuple[list[dict], dict, str, str]:
    tool_state = verify_tool("nmap")
    if not tool_state["installed"]:
        raise RuntimeError("nmap is not installed or not accessible on PATH")
    host = _extract_host(target_url)
    if mode == "quick":
        command = build_tool_command("nmap", "-Pn", "-T4", "-p", "80,443,8000,8080,8443", "-oX", "-", host)
    else:
        command = build_tool_command("nmap", "-Pn", "-T4", "-F", "-oX", "-", host)
    result = run_command(command)
    if result.returncode != 0:
        raise RuntimeError(f"Nmap failed: {result.stderr or result.stdout}")
    findings = parse_nmap_output(result.stdout)
    return findings, tool_state, result.stdout, result.stderr


def run_nikto(target_url: str, mode: str) -> tuple[list[dict], dict, str, str]:
    tool_state = verify_nikto()
    if not tool_state["installed"]:
        observation = {
            "title": "Nikto unavailable",
            "severity": "low",
            "score": 0.0,
            "finding_kind": "observation",
            "owasp_category": "A05:2021 - Security Misconfiguration",
            "confidence": "high",
            "file": target_url,
            "line_number": None,
            "description": "Nikto was skipped because Docker is not available on this host.",
            "evidence": "docker binary not detected",
            "tool": "nikto",
            "raw_json": {"reason": "docker_not_available"},
        }
        return [observation], tool_state, "", "Nikto skipped because Docker is not available."

    DOCKER_CONFIG.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent.parent / "data") as temp_dir:
        output_file = Path(temp_dir) / "nikto.json"
        tuning = "123bde" if mode == "quick" else "1234567890abcde"
        nikto_target = _nikto_target(target_url)
        command = build_tool_command(
            "docker",
            "run",
            "--rm",
            "-v",
            f"{temp_dir}:/out",
            "ghcr.io/sullo/nikto:latest",
            "-h",
            nikto_target,
            "-ask",
            "no",
            "-Format",
            "json",
            "-Tuning",
            tuning,
            "-timeout",
            "15",
            "-o",
            "/out/nikto.json",
        )
        nikto_timeout = 420 if mode == "quick" else 900
        result = run_command(command, env={"DOCKER_CONFIG": str(DOCKER_CONFIG)}, timeout=nikto_timeout)
        if result.returncode == -9:
            observation = {
                "title": "Nikto timed out",
                "severity": "low",
                "score": 0.0,
                "finding_kind": "observation",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "confidence": "high",
                "file": target_url,
                "line_number": None,
                "description": f"Nikto exceeded the scanner time limit ({nikto_timeout}s) before completing.",
                "evidence": "nikto_timeout",
                "tool": "nikto",
                "raw_json": {"timeout_seconds": nikto_timeout, "mode": mode},
            }
            return [observation], tool_state, result.stdout, result.stderr
        if result.returncode != 0:
            observation = {
                "title": "Nikto execution error",
                "severity": "low",
                "score": 0.0,
                "finding_kind": "observation",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "confidence": "medium",
                "file": target_url,
                "line_number": None,
                "description": "Nikto returned an execution error and did not produce complete findings.",
                "evidence": (result.stderr or result.stdout or "nikto_failed")[:500],
                "tool": "nikto",
                "raw_json": {"returncode": result.returncode},
            }
            return [observation], tool_state, result.stdout, result.stderr or "Nikto container execution failed."
        if not output_file.exists():
            observation = {
                "title": "Nikto report missing",
                "severity": "low",
                "score": 0.0,
                "finding_kind": "observation",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "confidence": "medium",
                "file": target_url,
                "line_number": None,
                "description": "Nikto finished without producing a JSON report file.",
                "evidence": "nikto_output_missing",
                "tool": "nikto",
                "raw_json": {"mode": mode},
            }
            return [observation], tool_state, result.stdout, "Nikto did not produce an output report."
        payload = json.loads(output_file.read_text(encoding="utf-8", errors="replace"))
        findings = parse_nikto_output(payload)
        findings = _rewrite_target_reference(findings, target_url, nikto_target)
        return findings, tool_state, json.dumps(payload, ensure_ascii=True), result.stderr


def enrich_with_owasp(findings: list[dict]) -> list[dict]:
    for item in findings:
        if not item.get("owasp_category"):
            item["owasp_category"] = infer_owasp(item.get("title"), item.get("description"), item.get("tool"))
    return findings


def _rewrite_target_reference(findings: list[dict], original_target: str, nikto_target: str) -> list[dict]:
    if original_target == nikto_target:
        return findings
    for item in findings:
        file_value = item.get("file")
        if isinstance(file_value, str):
            item["file"] = file_value.replace(nikto_target, original_target)
        evidence_value = item.get("evidence")
        if isinstance(evidence_value, str):
            item["evidence"] = evidence_value.replace(nikto_target, original_target)
    return findings

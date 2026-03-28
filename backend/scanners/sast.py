from __future__ import annotations

import os
import shutil
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ..parsers.sast import parse_bandit_output, parse_semgrep_output
from .base import build_tool_command, run_command, safe_json_loads, verify_tool

SEMGREP_RULES = Path(__file__).resolve().parent / "semgrep_rules.yml"
CODE_EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
}


@dataclass
class SourceStats:
    root: Path
    total_supported_files: int
    language_counts: dict[str, int]
    python_files: int


def _collapse_single_root(path: Path) -> Path:
    current = path
    while True:
        children = [child for child in current.iterdir() if child.name not in {".git", "__MACOSX"}]
        child_dirs = [child for child in children if child.is_dir()]
        child_files = [child for child in children if child.is_file()]
        if child_files or len(child_dirs) != 1:
            return current
        current = child_dirs[0]


def _scan_source_stats(source_dir: Path) -> SourceStats:
    root = _collapse_single_root(source_dir)
    counts: Counter[str] = Counter()
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        if any(part in {".git", "node_modules", "target", "build", "dist", "__pycache__"} for part in file_path.parts):
            continue
        language = CODE_EXTENSIONS.get(file_path.suffix.lower())
        if language:
            counts[language] += 1
    return SourceStats(
        root=root,
        total_supported_files=sum(counts.values()),
        language_counts=dict(counts),
        python_files=counts.get("python", 0),
    )


def build_sast_observations(stats: SourceStats) -> list[dict]:
    observations: list[dict] = []
    if stats.total_supported_files == 0:
        observations.append(
            {
                "title": "No supported source files detected",
                "severity": "low",
                "description": "The uploaded source did not contain supported Python, JavaScript, TypeScript, or Java files to scan.",
                "tool": "sast-engine",
                "finding_kind": "observation",
                "raw_json": {"root": str(stats.root)},
            }
        )
        return observations

    observations.append(
        {
            "title": "Source inventory",
            "severity": "low",
            "description": (
                f"Resolved source root: {stats.root}. "
                f"Detected supported files: {stats.total_supported_files}. "
                f"Languages: {stats.language_counts}."
            ),
            "tool": "sast-engine",
            "finding_kind": "observation",
            "raw_json": {
                "root": str(stats.root),
                "total_supported_files": stats.total_supported_files,
                "language_counts": stats.language_counts,
            },
        }
    )
    if stats.python_files == 0:
        observations.append(
            {
                "title": "Bandit skipped",
                "severity": "low",
                "description": "Bandit only scans Python. No Python files were detected in the source tree, so Bandit was skipped.",
                "tool": "bandit",
                "finding_kind": "observation",
                "raw_json": {"python_files": 0},
            }
        )
    return observations


def prepare_source(workspace: Path, source_type: str, target: str) -> Path:
    source_dir = workspace / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    if source_type == "github":
        git_path = shutil.which("git")
        if not git_path:
            raise RuntimeError("git is required to clone GitHub repositories for SAST scans")
        result = run_command([git_path, "clone", "--depth", "1", target, str(source_dir)])
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed: {result.stderr or result.stdout}")
        return source_dir
    zip_path = Path(target)
    if not zip_path.exists():
        raise RuntimeError("Uploaded ZIP archive was not found on disk")
    with zipfile.ZipFile(zip_path, "r") as archive:
        for member in archive.infolist():
            member_path = (source_dir / member.filename).resolve()
            if source_dir.resolve() not in member_path.parents and member_path != source_dir.resolve():
                raise RuntimeError("ZIP archive contains invalid paths")
        archive.extractall(source_dir)
    return _collapse_single_root(source_dir)


def run_semgrep(source_dir: Path) -> tuple[list[dict], dict, str, str]:
    tool_state = verify_tool("semgrep")
    if not tool_state["installed"]:
        raise RuntimeError("semgrep is not installed or not accessible on PATH")
    result = run_command(
        build_tool_command(
            "semgrep",
            "scan",
            "--config",
            str(SEMGREP_RULES),
            "--metrics",
            "off",
            "--disable-version-check",
            "--no-git-ignore",
            "--json",
            str(source_dir),
        ),
        env={
            "NO_COLOR": "1",
            "CI": "1",
        },
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError(f"Semgrep failed: {result.stderr or result.stdout}")
    if not result.stdout.strip():
        raise RuntimeError(f"Semgrep produced no JSON output: {result.stderr or 'empty stdout'}")
    stderr_text = result.stderr or ""
    if "Traceback" in stderr_text or "Fatal error:" in stderr_text or "Failed to " in stderr_text:
        raise RuntimeError(f"Semgrep failed: {result.stderr or result.stdout}")
    findings = parse_semgrep_output(safe_json_loads(result.stdout))
    return findings, tool_state, result.stdout, result.stderr


def run_bandit(source_dir: Path) -> tuple[list[dict], dict, str, str]:
    tool_state = verify_tool("bandit")
    if not tool_state["installed"]:
        raise RuntimeError("bandit is not installed or not accessible on PATH")
    result = run_command(build_tool_command("bandit", "-r", str(source_dir), "-f", "json"))
    if result.returncode not in {0, 1}:
        raise RuntimeError(f"Bandit failed: {result.stderr or result.stdout}")
    payload = safe_json_loads(result.stdout)
    if payload.get("errors"):
        raise RuntimeError(f"Bandit reported scan errors: {payload['errors']}")
    stderr_text = result.stderr or ""
    if "Bandit internal error" in stderr_text or "Traceback" in stderr_text:
        raise RuntimeError(f"Bandit failed: {result.stderr or result.stdout}")
    findings = parse_bandit_output(payload)
    return findings, tool_state, result.stdout, result.stderr

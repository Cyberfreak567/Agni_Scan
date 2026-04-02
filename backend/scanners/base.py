from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


logger = logging.getLogger("scanner-tools")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
VENV_SCRIPTS = PROJECT_ROOT / ".venv" / "Scripts"
LOCAL_TOOLS = PROJECT_ROOT / "backend" / "data" / "tools"
VENV_PYTHON = VENV_SCRIPTS / "python.exe"
USER_HOME = Path.home()
GLOBAL_PYTHON312 = USER_HOME / "AppData" / "Local" / "Programs" / "Python" / "Python312" / "python.exe"


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def _decode_output(raw: bytes | None) -> str:
    if raw is None:
        return ""
    for encoding in ("utf-8", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _common_tool_candidates(binary: str) -> list[Path]:
    exe_name = f"{binary}.exe"
    candidates: list[Path] = []
    if binary == "docker":
        candidates.extend(
            [
                Path("C:/Program Files/Docker/Docker/resources/bin") / exe_name,
                Path("C:/Program Files/Docker/resources/bin") / exe_name,
            ]
        )
    if binary == "nmap":
        candidates.extend(
            [
                Path("C:/Program Files (x86)/Nmap") / exe_name,
                Path("C:/Program Files/Nmap") / exe_name,
            ]
        )
    if binary == "nuclei":
        candidates.append(USER_HOME / "go" / "bin" / exe_name)
    return candidates


def resolve_tool(binary: str) -> str | None:
    found = shutil.which(binary)
    if found:
        return found
    candidates = [
        VENV_SCRIPTS / f"{binary}.exe",
        VENV_SCRIPTS / f"{binary}.cmd",
        VENV_SCRIPTS / binary,
        LOCAL_TOOLS / f"{binary}.exe",
        LOCAL_TOOLS / binary,
        *_common_tool_candidates(binary),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def verify_tool(binary: str) -> dict:
    if binary == "semgrep" and GLOBAL_PYTHON312.exists():
        return {"installed": True, "path": f"{GLOBAL_PYTHON312} -m semgrep.console_scripts.pysemgrep"}
    if binary == "bandit" and GLOBAL_PYTHON312.exists():
        return {"installed": True, "path": f"{GLOBAL_PYTHON312} -m bandit"}
    found = resolve_tool(binary)
    return {"installed": bool(found), "path": found}


def build_tool_command(binary: str, *args: str) -> list[str]:
    if binary == "semgrep" and GLOBAL_PYTHON312.exists():
        return [str(GLOBAL_PYTHON312), "-m", "semgrep.console_scripts.pysemgrep", *args]
    if binary == "bandit" and GLOBAL_PYTHON312.exists():
        return [str(GLOBAL_PYTHON312), "-m", binary, *args]
    if binary == "bandit" and VENV_PYTHON.exists():
        return [str(VENV_PYTHON), "-m", binary, *args]
    resolved = resolve_tool(binary)
    if not resolved:
        raise RuntimeError(f"{binary} is not installed or not accessible")
    return [resolved, *args]


def run_command(
    command: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> CommandResult:
    logger.info("Running command (timeout=%s): %s", timeout, command)
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=False,
            env=full_env,
            shell=False,
            check=False,
            timeout=timeout,
        )
        logger.info("Command finished with exit code %s", completed.returncode)
        return CommandResult(
            command=command,
            returncode=completed.returncode,
            stdout=_decode_output(completed.stdout),
            stderr=_decode_output(completed.stderr),
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("Command timed out after %s seconds: %s", timeout, command)
        return CommandResult(
            command=command,
            returncode=-9,
            stdout=_decode_output(exc.stdout),
            stderr=_decode_output(exc.stderr) + f"\n\nERROR: Command timed out after {timeout} seconds.",
        )


def safe_json_loads(raw: str) -> dict:
    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse tool JSON output: {exc}") from exc

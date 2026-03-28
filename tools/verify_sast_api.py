import json
import time
from pathlib import Path

import requests


BASE_URL = "http://127.0.0.1:8001"
USERNAME = "codex_sast_verify"
PASSWORD = "CodexPass123!"
ZIP_PATH = Path(r"C:\Users\Onkar sinha\Documents\New project\backend\data\runs\uploads\WebGoat-main.zip")


def main() -> None:
    response = requests.post(
        f"{BASE_URL}/api/auth/register",
        json={"username": USERNAME, "password": PASSWORD, "role": "admin"},
        timeout=30,
    )
    if response.status_code == 409:
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"username": USERNAME, "password": PASSWORD},
            timeout=30,
        )
    response.raise_for_status()
    token = response.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    with ZIP_PATH.open("rb") as handle:
        response = requests.post(
            f"{BASE_URL}/api/scans/sast",
            headers=headers,
            files={"file": (ZIP_PATH.name, handle, "application/zip")},
            timeout=120,
        )
    response.raise_for_status()
    scan_id = response.json()["scan_id"]
    print(f"SCAN_ID {scan_id}")

    for _ in range(120):
        response = requests.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers, timeout=30)
        response.raise_for_status()
        payload = response.json()
        print(f"STATUS {payload['status']} PROGRESS {payload['progress']} STAGE {payload.get('stage')}")
        if payload["status"] in {"completed", "failed"}:
            result = {
                "id": payload["id"],
                "status": payload["status"],
                "progress": payload["progress"],
                "stage": payload.get("stage"),
                "summary": payload.get("summary"),
                "tool_status": payload.get("tool_status"),
                "vulnerability_count": len(payload.get("vulnerabilities", [])),
                "logs_tail": (payload.get("logs") or "")[-4000:],
            }
            print(json.dumps(result, indent=2))
            return
        time.sleep(2)
    raise TimeoutError("Timed out waiting for SAST scan to finish")


if __name__ == "__main__":
    main()

import json
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen


BASE_URL = "http://127.0.0.1:8001"
USERNAME = "codex_sast_verify"
PASSWORD = "CodexPass123!"
ZIP_PATH = Path(r"C:\Users\Onkar sinha\Documents\New project\backend\data\runs\uploads\WebGoat-main.zip")


def _request(method: str, path: str, token: str | None = None, data: bytes | None = None, headers: dict[str, str] | None = None) -> Any:
    url = f"{BASE_URL}{path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    if token:
        req_headers["Authorization"] = f"Bearer {token}"
    if method == "GET":
        req = Request(url, method="GET", headers=req_headers)
    else:
        req = Request(url, data=data, method=method, headers=req_headers)
    try:
        with urlopen(req, timeout=30) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload)
    except HTTPError as exc:
        raise RuntimeError(f"{method} {path} failed {exc.code}") from exc


def _deploy_scan(token: str) -> int:
    headers = {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"}
    # fallback to a simple registration request when server already has the user
    payload = {"username": USERNAME, "password": PASSWORD, "role": "admin"}
    try:
        _request("POST", "/api/auth/register", data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
    except RuntimeError:
        pass
    login_payload = {"username": USERNAME, "password": PASSWORD}
    auth = _request("POST", "/api/auth/login", data=json.dumps(login_payload).encode("utf-8"))
    token = auth["token"]
    with ZIP_PATH.open("rb") as handle:
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{ZIP_PATH.name}"\r\n'
            "Content-Type: application/zip\r\n\r\n"
        ).encode("utf-8") + handle.read() + f"\r\n--{boundary}--\r\n".encode("utf-8")
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Authorization": f"Bearer {token}",
        }
        req = Request(f"{BASE_URL}/api/scans/sast", data=body, method="POST", headers=headers)
        with urlopen(req, timeout=120) as response:
            payload = json.loads(response.read().decode("utf-8"))
    return payload["scan_id"], token


def main() -> None:
    scan_id, token = _deploy_scan(None)
    print(f"SCAN_ID {scan_id}")
    for _ in range(120):
        payload = _request("GET", f"/api/scans/{scan_id}", token=token)
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

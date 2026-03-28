# Red Teaming Vulnerability Scanner

## Backend

1. Create a virtual environment.
2. Install dependencies with `pip install -r backend/requirements.txt`.
3. Start the API with `uvicorn backend.main:app --reload`.

## Frontend

1. Run `npm install` inside `frontend`.
2. Start the client with `npm run dev`.

## Scanner Requirements

The API verifies these tools before every scan:

- `semgrep`
- `bandit`
- `nuclei`
- `nmap`
- `docker` for Nikto in full DAST mode

If a required tool is missing, the scan is marked `failed` with captured logs instead of being reported as clean.

## DAST Modes

- `Quick`: HTTP baseline checks, focused Nmap web ports, focused Nuclei templates.
- `Full`: Quick checks plus broader Nuclei coverage and Docker-based Nikto.

Quick mode is intended to finish faster. Full mode can take several minutes on public targets.

## Local Validation Target

You can run the intentionally insecure demo target to verify the scanner with predictable findings:

```bat
.venv\Scripts\python.exe backend\demo_targets\insecure_app.py
```

Then launch a DAST scan against:

```text
http://127.0.0.1:8081
```

Expected findings include:

- plain HTTP service
- missing security headers
- password form over HTTP
- cookie security issues

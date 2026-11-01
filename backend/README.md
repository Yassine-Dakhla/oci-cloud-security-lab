# ForgeSec Scanner API

ForgeSec v1 performs lightweight external website checks for:

- HTTPS availability
- trusted TLS certificate and expiry
- negotiated TLS version and cipher
- HTTP to HTTPS redirect behavior
- HSTS
- Content-Security-Policy
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- clickjacking protection
- Server header exposure
- HTTPS response time

It does **not** exploit vulnerabilities, brute force paths, perform mass port scanning, or run intrusive payloads.

## Safety controls

- domain names only; direct IP targets are rejected
- localhost and internal-style names are rejected
- every resolved address must be globally routable
- the outbound connection is pinned to a pre-validated public address
- redirects are inspected but never followed
- short connection/read timeouts
- basic per-client in-memory rate limiting
- API binds to `127.0.0.1` and is intended to be exposed only through Nginx `/api/`

## Install on the OCI server

From the repository root:

```bash
cd ~/oci-cloud-security-lab/backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Test it locally:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

In another SSH session:

```bash
curl http://127.0.0.1:8000/api/health
```

Expected:

```json
{"status":"ok"}
```

Test a scan:

```bash
curl -s -X POST http://127.0.0.1:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com"}'
```

After local testing, install `forgesec.service.example` as a systemd service and add the `/api/` location from `../nginx/forgesec.conf.example` to the live Nginx configuration.

Do not expose port `8000` in OCI Security Lists or the host firewall. FastAPI should remain localhost-only.

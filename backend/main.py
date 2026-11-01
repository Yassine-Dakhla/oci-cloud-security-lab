from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(title="ForgeSec Scanner API", version="0.1.0", docs_url=None, redoc_url=None)

USER_AGENT = "ForgeSec/0.1 (+website-security-check)"
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_REQUESTS = 10
CONNECT_TIMEOUT_SECONDS = 5
READ_TIMEOUT_SECONDS = 7
MAX_HEADER_BYTES = 64 * 1024

_rate_buckets: dict[str, deque[float]] = defaultdict(deque)


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=253)


def client_ip(request: Request) -> str:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")


def enforce_rate_limit(request: Request) -> None:
    key = client_ip(request)
    now = time.monotonic()
    bucket = _rate_buckets[key]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(status_code=429, detail="Too many scans. Please try again in a minute.")
    bucket.append(now)


def normalize_hostname(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise HTTPException(status_code=400, detail="Enter a domain name.")

    parsed = urlsplit(value if "://" in value else f"https://{value}")
    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only HTTP and HTTPS targets are supported.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid port.") from exc

    if parsed.username or parsed.password or port not in {None, 80, 443}:
        raise HTTPException(status_code=400, detail="Credentials and custom ports are not supported.")

    host = parsed.hostname
    if not host:
        raise HTTPException(status_code=400, detail="Enter a valid domain name.")
    host = host.rstrip(".").lower()

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise HTTPException(status_code=400, detail="Direct IP scans are not supported in this version.")

    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise HTTPException(status_code=400, detail="Local or internal hostnames are not allowed.")

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid domain name.") from exc

    if len(host) > 253 or "." not in host:
        raise HTTPException(status_code=400, detail="Enter a public domain such as example.com.")

    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (char.isalnum() or char == "-") for char in label)
        for label in labels
    ):
        raise HTTPException(status_code=400, detail="Invalid domain name.")

    return host


async def resolve_public_addresses(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        answers = await asyncio.wait_for(
            loop.run_in_executor(None, socket.getaddrinfo, host, 443, 0, socket.SOCK_STREAM),
            timeout=4.0,
        )
    except (socket.gaierror, TimeoutError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=400, detail="The domain could not be resolved.") from exc

    addresses = sorted({answer[4][0] for answer in answers})
    if not addresses:
        raise HTTPException(status_code=400, detail="The domain did not resolve to an address.")

    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise HTTPException(
                status_code=400,
                detail="Targets resolving to private, local, reserved, or non-public addresses are blocked.",
            )
    return addresses


def parse_headers(raw: bytes) -> tuple[int, dict[str, str]]:
    text = raw.decode("iso-8859-1", errors="replace")
    lines = text.split("\r\n")
    if not lines or len(lines[0].split()) < 2:
        raise ValueError("Invalid HTTP response")
    status = int(lines[0].split()[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        clean = value.strip()
        headers[key] = f"{headers[key]}, {clean}" if key in headers else clean
    return status, headers


def tls_details_from_writer(writer: asyncio.StreamWriter) -> dict[str, Any]:
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return {"valid": False, "issuer": None, "expires_at": None, "days_remaining": None, "protocol": None, "cipher": None}

    cert = ssl_object.getpeercert()
    not_after_text = cert.get("notAfter")
    expires_at = None
    days_remaining = None
    if not_after_text:
        expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after_text), tz=timezone.utc)
        days_remaining = int((expires_at - datetime.now(timezone.utc)).total_seconds() // 86400)

    issuer = "Unknown"
    for group in cert.get("issuer", ()):
        for key, value in group:
            if key in {"organizationName", "commonName"}:
                issuer = value
                if key == "organizationName":
                    break

    cipher = ssl_object.cipher()
    return {
        "valid": True,
        "issuer": issuer,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "days_remaining": days_remaining,
        "protocol": ssl_object.version(),
        "cipher": cipher[0] if cipher else None,
    }


async def fetch_pinned(host: str, addresses: list[str], use_tls: bool) -> dict[str, Any]:
    port = 443 if use_tls else 80
    last_error: Exception | None = None

    for address in addresses:
        writer: asyncio.StreamWriter | None = None
        try:
            started = time.perf_counter()
            ssl_context = ssl.create_default_context() if use_tls else None
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=address,
                    port=port,
                    ssl=ssl_context,
                    server_hostname=host if use_tls else None,
                    limit=MAX_HEADER_BYTES,
                ),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )

            request_bytes = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                "Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.1\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            writer.write(request_bytes)
            await writer.drain()
            raw_headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=READ_TIMEOUT_SECONDS)
            if len(raw_headers) > MAX_HEADER_BYTES:
                raise ValueError("Response headers too large")

            status, headers = parse_headers(raw_headers)
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            tls = tls_details_from_writer(writer) if use_tls else None
            return {"status": status, "headers": headers, "response_time_ms": elapsed_ms, "tls": tls, "address": address}
        except (OSError, ssl.SSLError, asyncio.TimeoutError, ValueError, asyncio.LimitOverrunError, asyncio.IncompleteReadError) as exc:
            last_error = exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    raise ConnectionError(str(last_error) if last_error else "Connection failed")


def finding(fid: str, title: str, status: str, severity: str, detail: str, recommendation: str | None = None) -> dict[str, Any]:
    return {"id": fid, "title": title, "status": status, "severity": severity, "detail": detail, "recommendation": recommendation}


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan")
async def scan(payload: ScanRequest, request: Request) -> dict[str, Any]:
    enforce_rate_limit(request)
    host = normalize_hostname(payload.target)
    addresses = await resolve_public_addresses(host)

    http_result, https_result = await asyncio.gather(
        fetch_pinned(host, addresses, use_tls=False),
        fetch_pinned(host, addresses, use_tls=True),
        return_exceptions=True,
    )

    findings: list[dict[str, Any]] = []
    score = 0

    https_ok = not isinstance(https_result, Exception)
    if https_ok:
        https_status = https_result["status"]
        headers = https_result["headers"]
        response_time_ms = https_result["response_time_ms"]
        tls = https_result["tls"]
        score += 25
        findings.append(finding("https", "HTTPS available", "pass", "info", f"HTTPS responded with HTTP {https_status}."))
    else:
        https_status = None
        headers = {}
        response_time_ms = None
        tls = {"valid": False, "issuer": None, "expires_at": None, "days_remaining": None, "protocol": None, "cipher": None}
        findings.append(finding("https", "HTTPS available", "issue", "high", "ForgeSec could not establish a trusted HTTPS connection.", "Configure HTTPS with a valid certificate before serving sensitive traffic."))

    redirect_ok = False
    http_status = None
    if not isinstance(http_result, Exception):
        http_status = http_result["status"]
        location = http_result["headers"].get("location", "")
        if http_status in {301, 302, 303, 307, 308} and location:
            target = urlsplit(location if "://" in location else f"http://{host}{location}")
            redirect_ok = target.scheme.lower() == "https"

    if redirect_ok:
        score += 10
        findings.append(finding("redirect", "HTTP redirects to HTTPS", "pass", "info", "HTTP traffic is redirected to HTTPS."))
    else:
        findings.append(finding("redirect", "HTTP redirects to HTTPS", "warn", "medium", "A clear HTTP-to-HTTPS redirect was not detected.", "Redirect HTTP requests to the HTTPS version of the site."))

    if tls.get("valid"):
        days = tls.get("days_remaining")
        cert_status = "pass" if days is None or days > 14 else "warn"
        cert_severity = "info" if cert_status == "pass" else "medium"
        if cert_status == "pass":
            score += 15
        findings.append(finding("certificate", "TLS certificate", cert_status, cert_severity, f"Certificate is trusted and expires in approximately {days} days." if days is not None else "Certificate is trusted.", "Renew the certificate soon." if days is not None and days <= 14 else None))
    else:
        findings.append(finding("certificate", "TLS certificate", "issue", "high", "A trusted certificate could not be validated.", "Install or renew a certificate trusted for this hostname."))

    checks = [
        ("hsts", "Strict-Transport-Security", "strict-transport-security", 10, "medium", "Enable HSTS after confirming HTTPS works correctly across the site."),
        ("csp", "Content-Security-Policy", "content-security-policy", 10, "medium", "Deploy a Content-Security-Policy appropriate for the application."),
        ("nosniff", "X-Content-Type-Options", "x-content-type-options", 8, "low", "Set X-Content-Type-Options: nosniff."),
        ("referrer", "Referrer-Policy", "referrer-policy", 5, "low", "Set a Referrer-Policy appropriate for the site."),
        ("permissions", "Permissions-Policy", "permissions-policy", 5, "low", "Use Permissions-Policy to restrict browser features the site does not need."),
        ("frame", "Clickjacking protection", "x-frame-options", 5, "low", "Use frame-ancestors in CSP or an appropriate X-Frame-Options policy."),
    ]

    for fid, title, header_name, points, severity, recommendation in checks:
        value = headers.get(header_name)
        if fid == "frame" and not value and "frame-ancestors" in headers.get("content-security-policy", "").lower():
            value = "protected by CSP frame-ancestors"
        if value:
            score += points
            findings.append(finding(fid, title, "pass", "info", f"Detected: {value[:180]}"))
        else:
            findings.append(finding(fid, title, "warn", severity, f"{title} was not detected in the HTTPS response.", recommendation))

    server_header = headers.get("server")
    if server_header:
        findings.append(finding("server-header", "Server header exposure", "info", "info", f"The response advertises: {server_header[:120]}", "Consider minimizing unnecessary server-version disclosure where practical."))
    else:
        score += 5
        findings.append(finding("server-header", "Server header exposure", "pass", "info", "No Server header was observed."))

    score = min(100, score)
    counts = {
        "passed": sum(item["status"] == "pass" for item in findings),
        "warnings": sum(item["status"] == "warn" for item in findings),
        "issues": sum(item["status"] == "issue" for item in findings),
        "info": sum(item["status"] == "info" for item in findings),
    }
    grade = "Strong" if score >= 85 else "Good" if score >= 70 else "Needs attention" if score >= 50 else "Weak"

    return {
        "target": host,
        "score": score,
        "grade": grade,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "summary": counts,
        "http": {"status": http_status, "redirects_to_https": redirect_ok},
        "https": {"status": https_status, "response_time_ms": response_time_ms, "available": https_ok},
        "tls": tls,
        "dns": {"public_addresses_found": len(addresses)},
        "findings": findings,
        "scope_note": "ForgeSec v1 performs lightweight HTTP/TLS configuration checks only. It does not exploit vulnerabilities or run intrusive tests.",
    }

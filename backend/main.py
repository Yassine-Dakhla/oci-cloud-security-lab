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

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(
    title="ForgeSec Scanner API",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
)

USER_AGENT = "ForgeSec/0.1 (+website-security-check)"
REQUEST_TIMEOUT = httpx.Timeout(7.0, connect=5.0)
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_REQUESTS = 10

# In-memory rate limit is intentionally simple for v1. It resets when the API restarts.
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=253)


def client_ip(request: Request) -> str:
    # Nginx overwrites X-Real-IP before forwarding to the localhost-only API.
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

    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise HTTPException(status_code=400, detail="Only HTTP and HTTPS targets are supported.")
        host = parsed.hostname
        if parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
            raise HTTPException(status_code=400, detail="Credentials and custom ports are not supported.")
    else:
        parsed = urlsplit(f"https://{value}")
        host = parsed.hostname
        if parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
            raise HTTPException(status_code=400, detail="Credentials and custom ports are not supported.")

    if not host:
        raise HTTPException(status_code=400, detail="Enter a valid domain name.")

    host = host.rstrip(".").lower()

    # v1 deliberately accepts domain names only. Direct IP scans can be added later with ownership controls.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise HTTPException(status_code=400, detail="Direct IP scans are not supported in this version.")

    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise HTTPException(status_code=400, detail="Local or internal hostnames are not allowed.")

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid domain name.") from exc

    if len(ascii_host) > 253 or "." not in ascii_host:
        raise HTTPException(status_code=400, detail="Enter a public domain such as example.com.")

    labels = ascii_host.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (char.isalnum() or char == "-") for char in label)
        for label in labels
    ):
        raise HTTPException(status_code=400, detail="Invalid domain name.")

    return ascii_host


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
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise HTTPException(
                status_code=400,
                detail="Targets resolving to private, local, reserved, or non-public addresses are blocked.",
            )

    return addresses


async def fetch_headers(url: str) -> tuple[int, httpx.Headers, float]:
    started = time.perf_counter()
    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"},
    ) as client:
        async with client.stream("GET", url) as response:
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            return response.status_code, response.headers, elapsed_ms


def read_tls_certificate(host: str) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=5.0) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            cert = tls_socket.getpeercert()
            cipher = tls_socket.cipher()
            protocol = tls_socket.version()

    not_after_text = cert.get("notAfter")
    if not not_after_text:
        raise ssl.SSLError("Certificate expiry was not provided")

    expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after_text), tz=timezone.utc)
    days_remaining = max(0, int((expires_at - datetime.now(timezone.utc)).total_seconds() // 86400))

    issuer = "Unknown"
    for group in cert.get("issuer", ()):  # ((('commonName', 'Example CA'),), ...)
        for key, value in group:
            if key in {"organizationName", "commonName"}:
                issuer = value
                if key == "organizationName":
                    break

    return {
        "valid": True,
        "issuer": issuer,
        "expires_at": expires_at.isoformat(),
        "days_remaining": days_remaining,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else None,
    }


async def get_tls_details(host: str) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(asyncio.to_thread(read_tls_certificate, host), timeout=7.0)
    except (ssl.SSLError, socket.timeout, OSError, asyncio.TimeoutError) as exc:
        return {
            "valid": False,
            "issuer": None,
            "expires_at": None,
            "days_remaining": None,
            "protocol": None,
            "cipher": None,
            "error": str(exc),
        }


def finding(
    finding_id: str,
    title: str,
    status: str,
    severity: str,
    detail: str,
    recommendation: str | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "status": status,
        "severity": severity,
        "detail": detail,
        "recommendation": recommendation,
    }


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan")
async def scan(payload: ScanRequest, request: Request) -> dict[str, Any]:
    enforce_rate_limit(request)
    host = normalize_hostname(payload.target)
    resolved_addresses = await resolve_public_addresses(host)

    # We never follow redirects in v1. That keeps the scan limited to the submitted public host.
    try:
        http_result, https_result, tls = await asyncio.gather(
            fetch_headers(f"http://{host}/"),
            fetch_headers(f"https://{host}/"),
            get_tls_details(host),
            return_exceptions=True,
        )
    except Exception as exc:  # defensive fallback
        raise HTTPException(status_code=502, detail="The target could not be checked.") from exc

    findings: list[dict[str, Any]] = []
    score = 0

    https_ok = not isinstance(https_result, Exception)
    if https_ok:
        https_status, headers, response_time_ms = https_result
        score += 25
        findings.append(finding("https", "HTTPS available", "pass", "info", f"HTTPS responded with HTTP {https_status}."))
    else:
        headers = httpx.Headers()
        response_time_ms = None
        https_status = None
        findings.append(
            finding(
                "https",
                "HTTPS available",
                "issue",
                "high",
                "ForgeSec could not establish a trusted HTTPS connection.",
                "Configure HTTPS with a valid certificate before serving sensitive traffic.",
            )
        )

    redirect_ok = False
    http_status = None
    if not isinstance(http_result, Exception):
        http_status, http_headers, _ = http_result
        location = http_headers.get("location", "")
        if http_status in {301, 302, 303, 307, 308} and location:
            redirect_target = urlsplit(location if "://" in location else f"http://{host}{location}")
            redirect_ok = redirect_target.scheme.lower() == "https"

    if redirect_ok:
        score += 10
        findings.append(finding("redirect", "HTTP redirects to HTTPS", "pass", "info", "HTTP traffic is redirected to HTTPS."))
    else:
        findings.append(
            finding(
                "redirect",
                "HTTP redirects to HTTPS",
                "warn",
                "medium",
                "A clear HTTP-to-HTTPS redirect was not detected.",
                "Redirect HTTP requests to the HTTPS version of the site.",
            )
        )

    if tls.get("valid"):
        score += 15
        days = tls.get("days_remaining")
        findings.append(
            finding(
                "certificate",
                "TLS certificate",
                "pass" if days is None or days > 14 else "warn",
                "info" if days is None or days > 14 else "medium",
                f"Certificate is trusted and expires in approximately {days} days." if days is not None else "Certificate is trusted.",
                "Renew the certificate soon." if days is not None and days <= 14 else None,
            )
        )
    else:
        findings.append(
            finding(
                "certificate",
                "TLS certificate",
                "issue",
                "high",
                "A trusted certificate could not be validated.",
                "Install or renew a certificate trusted for this hostname.",
            )
        )

    header_checks = [
        ("hsts", "Strict-Transport-Security", "Strict-Transport-Security", 10, "medium", "Enable HSTS after confirming HTTPS works correctly across the site."),
        ("csp", "Content-Security-Policy", "Content-Security-Policy", 10, "medium", "Deploy a Content-Security-Policy appropriate for the application."),
        ("nosniff", "X-Content-Type-Options", "X-Content-Type-Options", 8, "low", "Set X-Content-Type-Options: nosniff."),
        ("referrer", "Referrer-Policy", "Referrer-Policy", 5, "low", "Set a Referrer-Policy appropriate for the site."),
        ("permissions", "Permissions-Policy", "Permissions-Policy", 5, "low", "Use Permissions-Policy to restrict browser features the site does not need."),
        ("frame", "Clickjacking protection", "X-Frame-Options", 5, "low", "Use frame-ancestors in CSP or an appropriate X-Frame-Options policy."),
    ]

    for finding_id, title, header_name, points, severity, recommendation in header_checks:
        value = headers.get(header_name)
        # CSP frame-ancestors is a modern replacement for X-Frame-Options.
        if finding_id == "frame" and not value:
            csp = headers.get("Content-Security-Policy", "")
            if "frame-ancestors" in csp.lower():
                value = "protected by CSP frame-ancestors"

        if value:
            score += points
            findings.append(finding(finding_id, title, "pass", "info", f"Detected: {value[:180]}"))
        else:
            findings.append(
                finding(
                    finding_id,
                    title,
                    "warn",
                    severity,
                    f"{header_name} was not detected in the HTTPS response.",
                    recommendation,
                )
            )

    server_header = headers.get("Server")
    if server_header:
        findings.append(
            finding(
                "server-header",
                "Server header exposure",
                "info",
                "info",
                f"The response advertises: {server_header[:120]}",
                "Consider minimizing unnecessary server-version disclosure where practical.",
            )
        )
    else:
        score += 5
        findings.append(finding("server-header", "Server header exposure", "pass", "info", "No Server header was observed."))

    score = min(100, score)
    counts = {
        "passed": sum(1 for item in findings if item["status"] == "pass"),
        "warnings": sum(1 for item in findings if item["status"] == "warn"),
        "issues": sum(1 for item in findings if item["status"] == "issue"),
        "info": sum(1 for item in findings if item["status"] == "info"),
    }

    if score >= 85:
        grade = "Strong"
    elif score >= 70:
        grade = "Good"
    elif score >= 50:
        grade = "Needs attention"
    else:
        grade = "Weak"

    return {
        "target": host,
        "score": score,
        "grade": grade,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "summary": counts,
        "http": {"status": http_status, "redirects_to_https": redirect_ok},
        "https": {"status": https_status, "response_time_ms": response_time_ms, "available": https_ok},
        "tls": tls,
        "dns": {"public_addresses_found": len(resolved_addresses)},
        "findings": findings,
        "scope_note": "ForgeSec v1 performs lightweight HTTP/TLS configuration checks only. It does not exploit vulnerabilities or run intrusive tests.",
    }

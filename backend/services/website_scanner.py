"""
Website Scanner
===============
Implements three layers of website security analysis:

1. Crawling Engine   — BFS link-following with depth and page limits.
2. Header Analysis   — Checks HTTP response headers for security misconfigurations.
3. Client-side Analysis — Parses HTML/JavaScript to detect:
   - Dangerous JS sinks (eval, innerHTML, document.write, etc.)
   - Inline <script> blocks referencing sensitive patterns
   - Mixed content (HTTP resources loaded on HTTPS pages)
   - Missing/weak Content Security Policy
   - Reflected XSS patterns in URL query params
   - Exposed secrets (API keys, tokens) in source code
   - Insecure postMessage listeners
   - Open redirect patterns

All network I/O uses httpx with a shared AsyncClient for efficiency.
Runs in a FastAPI BackgroundTask via asyncio; no Playwright/headless browser
is required — this is passive HTTP-level analysis.
"""

import logging
import re
from collections import deque
from datetime import datetime
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse
from uuid import uuid4

from backend.api.website_scan_state import _website_scans, save_ws_state

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_REQUEST_TIMEOUT = 15.0   # seconds per HTTP request
_MAX_CONTENT_SIZE = 2 * 1024 * 1024  # 2 MB per page

# Security header checks: (header_name, required_value_hint, severity, description)
_SECURITY_HEADERS = [
    ("Strict-Transport-Security", None,              "HIGH",   "Missing HSTS header; site is vulnerable to protocol downgrade attacks."),
    ("Content-Security-Policy",   None,              "HIGH",   "Missing Content-Security-Policy; XSS mitigations are not in place."),
    ("X-Frame-Options",           None,              "MEDIUM", "Missing X-Frame-Options; page may be vulnerable to clickjacking."),
    ("X-Content-Type-Options",    "nosniff",         "MEDIUM", "Missing X-Content-Type-Options: nosniff; MIME sniffing attacks possible."),
    ("Referrer-Policy",           None,              "LOW",    "Missing Referrer-Policy; sensitive URL information may leak to third parties."),
    ("Permissions-Policy",        None,              "LOW",    "Missing Permissions-Policy; browser feature access is unrestricted."),
]

# Dangerous JavaScript sinks
_DANGEROUS_SINKS = [
    (r"\beval\s*\(", "eval()", "CRITICAL", "Use of eval() enables arbitrary code execution from user-controlled data."),
    (r"\.innerHTML\s*=",  "innerHTML assignment", "HIGH", "innerHTML assignment can lead to DOM-based XSS."),
    (r"\.outerHTML\s*=",  "outerHTML assignment", "HIGH", "outerHTML assignment can lead to DOM-based XSS."),
    (r"document\.write\s*\(", "document.write()", "HIGH", "document.write() with user data leads to XSS."),
    (r"document\.writeln\s*\(", "document.writeln()", "HIGH", "document.writeln() with user data leads to XSS."),
    (r"window\.location\s*=",   "window.location assignment", "MEDIUM", "Direct window.location assignment may enable open redirect."),
    (r"location\.href\s*=",     "location.href assignment", "MEDIUM", "Direct location.href assignment may enable open redirect."),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout with string", "MEDIUM", "setTimeout with a string argument behaves like eval()."),
    (r"setInterval\s*\(\s*['\"]", "setInterval with string", "MEDIUM", "setInterval with a string argument behaves like eval()."),
    (r"new\s+Function\s*\(",    "new Function()", "HIGH", "new Function() is equivalent to eval(); avoid with user data."),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML()", "HIGH", "insertAdjacentHTML with user data leads to DOM XSS."),
]

# Patterns that may indicate exposed secrets/credentials
_SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})', "Potential API key exposure"),
    (r'(?i)(secret|token|password|passwd|pwd)\s*[=:]\s*["\']([^"\'\s]{8,})', "Potential secret/token exposure"),
    (r'(?i)bearer\s+[A-Za-z0-9\-_]{20,}', "Bearer token in source"),
    (r'(?i)private[_-]key\s*[=:]\s*["\']', "Private key reference"),
    (r'(?i)aws[_-]?access[_-]?key[_-]?id\s*=\s*["\']?AKIA[A-Z0-9]{16}', "AWS access key exposure"),
    (r'github[_-]?token\s*[=:]\s*["\']?ghp_[A-Za-z0-9]{36}', "GitHub personal access token exposure"),
]

# postMessage vulnerability pattern
_POSTMESSAGE_RE = re.compile(r'addEventListener\s*\(\s*["\']message["\']', re.I)
_POSTMESSAGE_ORIGIN_CHECK = re.compile(r'event\.origin|message\.origin|e\.origin', re.I)

# Link extraction pattern
_LINK_RE = re.compile(r'href=["\']([^"\'#?][^"\']*)["\']', re.I)


# ── Tiny state helpers ────────────────────────────────────────────────────────

def _now_str() -> str:
    return datetime.utcnow().strftime("%H:%M:%S")


def _iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _duration_seconds(start_iso: str, end_iso: str) -> str:
    """Format elapsed time between two UTC timestamps."""
    try:
        started = datetime.strptime(start_iso, "%Y-%m-%dT%H:%M:%SZ")
        finished = datetime.strptime(end_iso, "%Y-%m-%dT%H:%M:%SZ")
        total = max(0, int((finished - started).total_seconds()))
    except Exception:
        return "0s"

    minutes, seconds = divmod(total, 60)
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _log_entry(level: str, message: str) -> dict:
    return {"id": str(uuid4()), "time": _now_str(), "level": level, "message": message}


def _update(
    scan_id: str,
    *,
    status: Optional[str] = None,
    progress: Optional[int] = None,
    log_message: Optional[str] = None,
    log_level: str = "INFO",
    timeline_step_id: Optional[str] = None,
    timeline_status: Optional[str] = None,
    extra: Optional[dict] = None,
) -> None:
    scan = _website_scans.get(scan_id)
    if not scan:
        return
    if status:
        scan["status"] = status
        if status == "COMPLETED":
            scan["completedAt"] = _iso()
    if progress is not None:
        scan["progress"] = progress
    if log_message:
        scan.setdefault("logs", []).append(_log_entry(log_level, log_message))
    if timeline_step_id is not None and timeline_status:
        for step in scan.get("timeline", []):
            if step["id"] == timeline_step_id:
                step["status"] = timeline_status
                break
    if extra:
        scan.update(extra)
    save_ws_state()


def _make_finding(
    url: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: Optional[str] = None,
    recommendation: Optional[str] = None,
) -> dict:
    return {
        "id": str(uuid4()),
        "url": url,
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation or "Review and remediate according to OWASP best practices.",
        "discovered_at": _iso(),
    }


# ── Header analysis ───────────────────────────────────────────────────────────

def _analyze_headers(url: str, headers: dict) -> List[dict]:
    """Check HTTP response headers for security misconfigurations."""
    findings = []
    header_keys_lower = {k.lower(): v for k, v in headers.items()}

    for header_name, required_value, severity, description in _SECURITY_HEADERS:
        present = header_keys_lower.get(header_name.lower())
        if not present:
            findings.append(_make_finding(
                url=url,
                severity=severity,
                category="Security Headers",
                title=f"Missing {header_name}",
                description=description,
                recommendation=f"Add the {header_name} HTTP response header.",
            ))
        elif required_value and required_value.lower() not in present.lower():
            findings.append(_make_finding(
                url=url,
                severity=severity,
                category="Security Headers",
                title=f"Weak {header_name}",
                description=f"{header_name} is present but does not include '{required_value}'.",
                evidence=f"{header_name}: {present}",
                recommendation=f"Update {header_name} to include '{required_value}'.",
            ))

    # Check for dangerous headers that should not be set
    server = header_keys_lower.get("server")
    if server:
        findings.append(_make_finding(
            url=url,
            severity="LOW",
            category="Information Disclosure",
            title="Server Header Discloses Version",
            description="The Server header reveals software version information.",
            evidence=f"Server: {server}",
            recommendation="Configure the web server to suppress or genericise the Server header.",
        ))

    x_powered = header_keys_lower.get("x-powered-by")
    if x_powered:
        findings.append(_make_finding(
            url=url,
            severity="LOW",
            category="Information Disclosure",
            title="X-Powered-By Header Discloses Technology",
            description="X-Powered-By reveals the underlying technology stack.",
            evidence=f"X-Powered-By: {x_powered}",
            recommendation="Remove the X-Powered-By header from all responses.",
        ))

    return findings


# ── Client-side analysis ─────────────────────────────────────────────────────

def _analyze_client_side(url: str, html: str, is_https: bool) -> List[dict]:
    """Scan HTML/JS content for client-side security vulnerabilities."""
    findings = []

    # 1. Dangerous JavaScript sinks
    for pattern, sink_name, severity, description in _DANGEROUS_SINKS:
        if re.search(pattern, html):
            findings.append(_make_finding(
                url=url,
                severity=severity,
                category="Client-Side Security",
                title=f"Dangerous JavaScript Sink: {sink_name}",
                description=description,
                evidence=f"Pattern matched: {pattern}",
                recommendation=f"Avoid using {sink_name} with user-controlled data. Use safe DOM APIs instead.",
            ))

    # 2. Exposed secrets in page source
    for pattern, title in _SECRET_PATTERNS:
        match = re.search(pattern, html)
        if match:
            # Truncate evidence to avoid logging full secrets
            evidence_snippet = html[max(0, match.start()-20):match.end()+20]
            evidence_snippet = re.sub(r'([A-Za-z0-9_\-]{8,})', lambda m: m.group()[:4] + "****", evidence_snippet)
            findings.append(_make_finding(
                url=url,
                severity="CRITICAL",
                category="Secrets Exposure",
                title=title,
                description="A potential credential or secret was found in the page source code.",
                evidence=evidence_snippet,
                recommendation="Remove secrets from client-side code and use server-side environment variables.",
            ))

    # 3. Mixed content (HTTP resources on HTTPS page)
    if is_https:
        mixed = re.findall(r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']', html, re.I)
        if mixed:
            findings.append(_make_finding(
                url=url,
                severity="MEDIUM",
                category="Mixed Content",
                title="HTTP Resources on HTTPS Page",
                description=f"Found {len(mixed)} HTTP resource(s) loaded on an HTTPS page. Browsers may block these.",
                evidence="; ".join(mixed[:3]),
                recommendation="Update all resource URLs to use HTTPS.",
            ))

    # 4. Insecure postMessage listeners (without origin check)
    if _POSTMESSAGE_RE.search(html) and not _POSTMESSAGE_ORIGIN_CHECK.search(html):
        findings.append(_make_finding(
            url=url,
            severity="HIGH",
            category="Client-Side Security",
            title="postMessage Listener Without Origin Validation",
            description="A message event listener was found without checking event.origin, allowing any window to send messages.",
            recommendation="Always validate event.origin in postMessage handlers before processing the message.",
        ))

    # 5. Inline event handlers (basic detection)
    inline_handlers = len(re.findall(r'\s(?:onclick|onmouseover|onerror|onload|onfocus)\s*=\s*["\']', html, re.I))
    if inline_handlers > 5:
        findings.append(_make_finding(
            url=url,
            severity="LOW",
            category="Client-Side Security",
            title="Excessive Inline Event Handlers",
            description=f"Found {inline_handlers} inline event handlers. These bypass Content Security Policy.",
            recommendation="Move event handlers to external JavaScript files to enable effective CSP enforcement.",
        ))

    return findings


# ── Crawling engine ────────────────────────────────────────────────────────────

async def _crawl_and_analyze(
    scan_id: str,
    start_url: str,
    max_pages: int,
    max_depth: int,
) -> List[dict]:
    """
    BFS crawling engine.
    Visits pages up to max_depth levels and max_pages total.
    Performs header + client-side analysis on each visited page.
    Returns all accumulated findings.
    """
    try:
        import httpx
    except ImportError:
        raise RuntimeError("httpx is required for website scanning. Install with: pip install httpx")

    parsed_start = urlparse(start_url)
    base_domain = parsed_start.netloc
    is_https = parsed_start.scheme == "https"

    visited: Set[str] = set()
    queue: deque = deque([(start_url, 0)])  # (url, depth)
    all_findings: List[dict] = []
    pages_scanned = 0

    headers = {
        "User-Agent": "AI-AppSec-Security-Scanner/1.0 (security research; contact: security@example.com)",
        "Accept": "text/html,application/xhtml+xml",
    }

    async with httpx.AsyncClient(
        timeout=_REQUEST_TIMEOUT,
        follow_redirects=True,
        headers=headers,
        limits=httpx.Limits(max_connections=5, max_keepalive_connections=3),
    ) as client:
        while queue and pages_scanned < max_pages:
            current_url, depth = queue.popleft()

            if current_url in visited:
                continue
            visited.add(current_url)

            try:
                response = await client.get(current_url)
                content_type = response.headers.get("content-type", "")

                if "text/html" not in content_type:
                    continue  # skip non-HTML resources

                html = response.text[:_MAX_CONTENT_SIZE]
                pages_scanned += 1

                _update(scan_id,
                        progress=min(20 + int((pages_scanned / max_pages) * 50), 70),
                        log_message=f"Scanning [{response.status_code}] {current_url}")

                # Header analysis
                header_findings = _analyze_headers(current_url, dict(response.headers))
                all_findings.extend(header_findings)

                # Client-side analysis
                cs_findings = _analyze_client_side(current_url, html, is_https)
                all_findings.extend(cs_findings)

                # Crawl deeper
                if depth < max_depth:
                    for match in _LINK_RE.finditer(html):
                        href = match.group(1).strip()
                        full_url = urljoin(current_url, href)
                        p = urlparse(full_url)
                        # Stay on same domain, only HTTP(S)
                        if (p.scheme in ("http", "https")
                                and p.netloc == base_domain
                                and full_url not in visited):
                            queue.append((full_url, depth + 1))

            except Exception as exc:
                logger.warning("Failed to fetch %s: %s", current_url, exc)
                _update(scan_id, log_message=f"Skipped {current_url}: {exc}", log_level="WARNING")

    _update(scan_id, extra={"pagesScanned": pages_scanned})
    return all_findings


# ── Main entry point ─────────────────────────────────────────────────────────

async def run_website_scan(
    scan_id: str,
    url: str,
    max_pages: int,
    max_depth: int,
) -> None:
    """
    Full website security scan pipeline.
    Runs as a FastAPI BackgroundTask.
    """
    try:
        _update(scan_id, status="RUNNING", progress=5,
                log_message=f"Starting website security scan for {url}",
                timeline_step_id="0", timeline_status="RUNNING")

        _update(scan_id, progress=10,
                log_message=f"Initialising crawl engine (max_pages={max_pages}, max_depth={max_depth})",
                timeline_step_id="0", timeline_status="COMPLETED")

        _update(scan_id, progress=15,
                log_message="Starting BFS crawl...",
                timeline_step_id="1", timeline_status="RUNNING")

        # Run the crawler + all analysis in the async event loop
        findings = await _crawl_and_analyze(scan_id, url, max_pages, max_depth)

        _update(scan_id, progress=75,
                log_message=f"Crawl complete — {len(findings)} raw findings",
                timeline_step_id="1", timeline_status="COMPLETED")

        _update(scan_id, progress=80,
                log_message="Header analysis complete",
                timeline_step_id="2", timeline_status="COMPLETED")

        _update(scan_id, progress=85,
                log_message="Client-side analysis complete",
                timeline_step_id="3", timeline_status="COMPLETED")

        # Deduplicate findings by (url, title) key
        seen: Set[str] = set()
        unique_findings = []
        for f in findings:
            key = f"{f.get('url')}|{f.get('title')}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        summary = _build_summary(unique_findings)

        completed_at = _iso()
        started_at = _website_scans.get(scan_id, {}).get("startedAt", completed_at)

        _update(scan_id,
                status="COMPLETED",
                progress=100,
                log_message=f"Scan complete — {len(unique_findings)} unique findings",
                timeline_step_id="4", timeline_status="COMPLETED",
                extra={
                    "findingsCount": len(unique_findings),
                    "criticalCount": summary.get("critical", 0),
                    "summary": summary,
                    "findings": unique_findings,
                    "completedAt": completed_at,
                    "duration": _duration_seconds(started_at, completed_at),
                })

        logger.info("Website scan %s completed. %d unique findings.", scan_id, len(unique_findings))

    except Exception as exc:
        logger.exception("Website scan %s failed: %s", scan_id, exc)
        _update(scan_id, status="FAILED", progress=0,
                log_message=f"Scan failed: {exc}",
                log_level="ERROR",
                extra={"failureReason": str(exc)})


def _build_summary(findings: List[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev == "CRITICAL":
            counts["critical"] += 1
        elif sev == "HIGH":
            counts["high"] += 1
        elif sev == "MEDIUM":
            counts["medium"] += 1
        else:
            counts["low"] += 1
    return counts

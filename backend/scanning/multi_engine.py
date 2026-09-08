"""Multi-engine repository scanning and finding correlation.

The adapters intentionally normalize external scanner output into the finding
shape already consumed by the enrichment, risk, and persistence layers. A
missing optional binary is represented as an unavailable engine rather than a
scan failure.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

ENGINE_TIMEOUT_SECONDS = 600
OPTIONAL_ENGINES = ("gitleaks", "bandit", "trivy", "osv-scanner", "npm-audit", "pip-audit")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_text(item) for item in value if item is not None)
    return str(value)


def _severity(value: Any) -> str:
    normalized = _text(value).upper()
    aliases = {"ERROR": "HIGH", "WARNING": "MEDIUM", "WARN": "MEDIUM", "INFO": "LOW"}
    return aliases.get(normalized, normalized or "INFO")


def _location(item: dict) -> tuple[str, Optional[int]]:
    location = item.get("location") or {}
    file_path = (
        item.get("path")
        or item.get("file")
        or item.get("filename")
        or location.get("path")
        or location.get("file")
        or ""
    )
    line = item.get("line") or item.get("start_line") or item.get("line_number")
    if not line and isinstance(location, dict):
        start = location.get("start") or {}
        line = start.get("line") or location.get("line")
    if not line:
        line = (item.get("start") or {}).get("line")
    try:
        line = int(line) if line else None
    except (TypeError, ValueError):
        line = None
    return str(file_path).replace("\\", "/"), line


def normalize_finding(engine: str, item: dict) -> dict:
    """Convert one engine-specific result to the platform's finding shape."""
    path, line = _location(item)
    rule_id = (
        item.get("rule_id")
        or item.get("check_id")
        or item.get("test_id")
        or item.get("ruleId")
        or item.get("id")
        or item.get("vulnerability", {}).get("id")
        or item.get("issue", {}).get("id")
        or f"{engine}.finding"
    )
    message = (
        item.get("message")
        or item.get("description")
        or item.get("issue_text")
        or item.get("title")
        or item.get("details")
        or item.get("extra", {}).get("message")
        or item.get("issue", {}).get("text")
        or "Security finding"
    )
    cve = item.get("cve") or item.get("vulnerability", {}).get("id")
    cwe = item.get("cwe") or item.get("metadata", {}).get("cwe")
    severity = _severity(
        item.get("severity")
        or item.get("priority")
        or item.get("issue_severity")
        or item.get("vulnerability", {}).get("severity")
        or item.get("issue", {}).get("severity")
    )

    finding = {
        "rule_id": str(rule_id),
        "severity": severity,
        "path": path,
        "line": line,
        "message": _text(message),
        "cwe": cwe if isinstance(cwe, list) else ([cwe] if cwe else []),
        "scanner": engine,
        "engine": engine,
        "engine_evidence": {engine: item},
    }
    if cve:
        finding["cve"] = str(cve)
    return {"finding": finding, "raw_engine_payload": item}


def _semgrep_findings(payload: dict) -> list[dict]:
    results = []
    for item in payload.get("results", []):
        normalized = normalize_finding("semgrep", item)
        finding = normalized["finding"]
        start = item.get("start") or {}
        finding["line"] = start.get("line") or finding["line"]
        finding["metadata"] = item.get("extra", {}).get("metadata", {})
        finding["message"] = item.get("extra", {}).get("message") or finding["message"]
        results.append(normalized)
    return results


def _gitleaks_findings(payload: Any) -> list[dict]:
    return [normalize_finding("gitleaks", item) for item in (payload if isinstance(payload, list) else [])]


def _bandit_findings(payload: dict) -> list[dict]:
    return [normalize_finding("bandit", item) for item in payload.get("results", [])]


def _trivy_findings(payload: dict) -> list[dict]:
    findings = []
    for result in payload.get("Results", []) or []:
        target = result.get("Target", "")
        for item in result.get("Vulnerabilities", []) or []:
            item = dict(item)
            item.setdefault("path", target)
            findings.append(normalize_finding("trivy", item))
    return findings


def _osv_findings(payload: dict) -> list[dict]:
    findings = []
    for result in payload.get("results", []) or []:
        source = result.get("source", {}).get("path", "")
        for package in result.get("packages", []) or []:
            for vuln in package.get("vulnerabilities", []) or []:
                item = dict(vuln)
                item.setdefault("path", source)
                item.setdefault("description", vuln.get("summary"))
                findings.append(normalize_finding("osv-scanner", item))
    return findings


def _npm_findings(payload: dict) -> list[dict]:
    findings = []
    for name, item in (payload.get("vulnerabilities") or {}).items():
        item = dict(item)
        item.setdefault("id", name)
        item.setdefault("path", "package-lock.json")
        item.setdefault("severity", item.get("severity", "MEDIUM"))
        findings.append(normalize_finding("npm-audit", item))
    return findings


def _pip_findings(payload: Any) -> list[dict]:
    items = payload.get("dependencies", []) if isinstance(payload, dict) else payload
    return [normalize_finding("pip-audit", item) for item in (items or []) if item.get("vulns")]


def _command_for(engine: str, scan_path: Path, output_path: Path) -> Optional[list[str]]:
    commands = {
        "gitleaks": ["gitleaks", "detect", "--source", str(scan_path), "--report-format", "json", "--report-path", str(output_path), "--no-banner"],
        "bandit": ["bandit", "-r", str(scan_path), "-f", "json", "-o", str(output_path)],
        "trivy": ["trivy", "fs", "--format", "json", "--output", str(output_path), str(scan_path)],
        "osv-scanner": ["osv-scanner", "--format", "json", "--output", str(output_path), "--recursive", str(scan_path)],
    }
    if engine in commands:
        return commands[engine]
    if engine == "npm-audit" and (scan_path / "package-lock.json").exists():
        return ["npm", "audit", "--json"]
    if engine == "pip-audit" and any((scan_path / name).exists() for name in ("requirements.txt", "pyproject.toml", "Pipfile")):
        return ["pip-audit", "--format", "json"]
    return None


def _run_optional_engine(engine: str, scan_path: Path, work_dir: Path) -> tuple[list[dict], str]:
    executable = "npm" if engine == "npm-audit" else engine
    if not shutil.which(executable):
        return [], "unavailable"
    output_path = work_dir / f"{engine}.json"
    command = _command_for(engine, scan_path, output_path)
    if command is None:
        return [], "not-applicable"
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=ENGINE_TIMEOUT_SECONDS,
            cwd=scan_path,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        raw = result.stdout
        if output_path.exists():
            raw = output_path.read_text(encoding="utf-8", errors="ignore")
        payload = json.loads(raw or "[]")
        parsers = {
            "gitleaks": _gitleaks_findings,
            "bandit": _bandit_findings,
            "trivy": _trivy_findings,
            "osv-scanner": _osv_findings,
            "npm-audit": _npm_findings,
            "pip-audit": _pip_findings,
        }
        return parsers[engine](payload), "completed"
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.warning("%s adapter failed: %s", engine, exc)
        return [], "failed"


def _correlation_key(finding: dict) -> str:
    item = finding.get("finding", {})
    identity = "|".join(
        [
            str(item.get("path", "")).lower(),
            str(item.get("line") or "").lower(),
            str(item.get("cve") or item.get("rule_id") or "").lower(),
            str(item.get("message", "")).lower()[:120],
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def correlate_findings(findings: Iterable[dict]) -> list[dict]:
    """Merge cross-engine matches while preserving evidence from each engine."""
    groups: dict[str, list[dict]] = {}
    for finding in findings:
        groups.setdefault(_correlation_key(finding), []).append(finding)

    correlated = []
    for key, group in groups.items():
        representative = dict(group[0])
        item = dict(representative.get("finding", {}))
        engines = sorted({entry.get("finding", {}).get("engine", "unknown") for entry in group})
        evidence: dict[str, list[dict]] = {}
        for entry in group:
            engine = entry.get("finding", {}).get("engine", "unknown")
            evidence.setdefault(engine, []).append(entry.get("raw_engine_payload", {}))
        confidence = min(99, 60 + (len(engines) - 1) * 15)
        item.update({"detected_by": engines, "engine_count": len(engines), "confidence_score": confidence})
        representative["finding"] = item
        representative["correlation_key"] = key
        representative["detected_by"] = engines
        representative["engine_count"] = len(engines)
        representative["confidence_score"] = confidence
        representative["engine_evidence"] = evidence
        representative["related_engine_findings"] = [entry for entry in group[1:]]
        correlated.append(representative)
    return correlated


def run_multi_engine_scan(scan_path: Path, semgrep_payload: dict, work_dir: Path) -> dict:
    """Run available secondary engines and return correlated normalized findings."""
    work_dir.mkdir(parents=True, exist_ok=True)
    findings = _semgrep_findings(semgrep_payload)
    statuses = {"semgrep": "completed"}
    for engine in OPTIONAL_ENGINES:
        engine_findings, status = _run_optional_engine(engine, scan_path, work_dir)
        statuses[engine] = status
        findings.extend(engine_findings)
    return {
        "findings": correlate_findings(findings),
        "raw_finding_count": len(findings),
        "correlated_finding_count": len(correlate_findings(findings)),
        "engine_status": statuses,
        "engines_used": sorted({item.get("finding", {}).get("engine") for item in findings}),
    }

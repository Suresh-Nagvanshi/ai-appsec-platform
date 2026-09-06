"""Unified security graph API.

Builds a read-only graph from persisted scan and finding records. The graph is
intended for investigation and prioritization: edges show evidence already
present in scan data, while attack paths are explicitly labelled as candidates.
"""

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from backend.storage.findings_repository import FindingsRepository

router = APIRouter()
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_REPOSITORY_DIR = _BASE_DIR / "database" / "repositories"


def _finding_parts(finding: dict) -> tuple[dict, dict, dict]:
    representative = finding.get("representative_finding") or {}
    raw = representative.get("finding") or finding.get("finding") or finding
    risk = representative.get("risk") or finding.get("risk") or {}
    endpoint = representative.get("endpoint") or finding.get("endpoint") or {}
    return raw, risk, endpoint


def _node(node_id: str, node_type: str, label: str, **attributes: Any) -> dict:
    return {"id": node_id, "type": node_type, "label": label, "attributes": attributes}


def build_security_graph(
    scans: list[dict],
    findings: list[dict],
    repositories: list[dict] | None = None,
) -> dict:
    """Build stable nodes, edges, and candidate attack paths from scan data."""
    nodes: dict[str, dict] = {}
    edges: set[tuple[str, str, str]] = set()
    repositories = repositories or []
    scan_by_id = {str(scan.get("scan_id") or scan.get("id")): scan for scan in scans}

    for repository in repositories:
        repository_id = f"repository:{repository['id']}"
        nodes[repository_id] = _node(
            repository_id,
            "repository",
            repository.get("name") or repository.get("url", "Repository"),
            url=repository.get("url"),
            status=repository.get("status"),
        )

    for scan in scans:
        scan_id = str(scan.get("scan_id") or scan.get("id"))
        if scan_id == "None":
            continue
        scan_node = f"scan:{scan_id}"
        nodes[scan_node] = _node(
            scan_node,
            "scan",
            scan.get("project_name") or scan.get("target") or scan_id,
            scan_id=scan_id,
            scan_type=scan.get("scan_type") or scan.get("scanType"),
            status=scan.get("status", "COMPLETED"),
        )
        source_url = scan.get("source_url") or scan.get("target")
        for repository in repositories:
            if source_url and source_url == repository.get("url"):
                edges.add((f"repository:{repository['id']}", scan_node, "scanned"))

    attack_candidates = []
    for finding in findings:
        finding_id = str(finding.get("id", ""))
        scan_id = str(finding.get("scan_id", ""))
        if not finding_id:
            continue
        raw, risk, endpoint = _finding_parts(finding)
        finding_node = f"finding:{finding_id}"
        severity = str(risk.get("severity") or raw.get("severity") or "INFO").upper()
        score = float(risk.get("risk_score") or finding.get("risk_score") or 0)
        nodes[finding_node] = _node(
            finding_node,
            "finding",
            raw.get("message") or raw.get("rule_id") or "Security finding",
            finding_id=finding_id,
            severity=severity,
            risk_score=score,
            status=finding.get("status", "open"),
            file=raw.get("path"),
            line=raw.get("line"),
        )
        if f"scan:{scan_id}" in nodes:
            edges.add((f"scan:{scan_id}", finding_node, "contains"))

        endpoint_path = endpoint.get("endpoint") or endpoint.get("path")
        if endpoint_path:
            endpoint_id = f"endpoint:{endpoint.get('method', 'REQUEST')}:{endpoint_path}"
            nodes.setdefault(
                endpoint_id,
                _node(
                    endpoint_id,
                    "endpoint",
                    endpoint_path,
                    method=endpoint.get("method", "REQUEST"),
                    framework=endpoint.get("framework"),
                ),
            )
            edges.add((finding_node, endpoint_id, "affects"))

            if severity in {"CRITICAL", "HIGH", "ERROR"} and endpoint.get("exposure") != "internal":
                attack_candidates.append({
                    "finding_id": finding_id,
                    "endpoint_id": endpoint_id,
                    "severity": severity,
                    "risk_score": score,
                    "reason": "High-risk finding affects a discovered endpoint.",
                })

        for reference_key, node_type in (("cwe", "cwe"), ("owasp", "owasp"), ("mitre", "mitre")):
            references = raw.get(reference_key) or finding.get(reference_key) or []
            if isinstance(references, str):
                references = [references]
            for reference in references:
                reference_id = f"{node_type}:{reference}"
                nodes.setdefault(reference_id, _node(reference_id, node_type, str(reference)))
                edges.add((finding_node, reference_id, "mapped_to"))

    attack_candidates.sort(key=lambda item: (-item["risk_score"], item["finding_id"]))
    return {
        "nodes": list(nodes.values()),
        "edges": [
            {"source": source, "target": target, "type": edge_type}
            for source, target, edge_type in sorted(edges)
        ],
        "attack_paths": attack_candidates,
        "summary": {
            "repositories": sum(node["type"] == "repository" for node in nodes.values()),
            "scans": sum(node["type"] == "scan" for node in nodes.values()),
            "findings": sum(node["type"] == "finding" for node in nodes.values()),
            "endpoints": sum(node["type"] == "endpoint" for node in nodes.values()),
            "attack_path_candidates": len(attack_candidates),
        },
    }


def _load_repositories() -> list[dict]:
    records = []
    for path in _REPOSITORY_DIR.glob("*.json"):
        try:
            records.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return records


@router.get("")
def get_security_graph(scan_id: str | None = None):
    """Return the unified security graph, optionally scoped to one scan."""
    repository = FindingsRepository()
    scans = repository.list_scans()
    findings = repository.get_all_findings()
    if scan_id:
        scans = [scan for scan in scans if str(scan.get("scan_id") or scan.get("id")) == scan_id]
        findings = [finding for finding in findings if str(finding.get("scan_id")) == scan_id]
        if not scans and not findings:
            raise HTTPException(status_code=404, detail="Scan not found")
    return build_security_graph(scans, findings, _load_repositories())

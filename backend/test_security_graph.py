from backend.api.security_graph import build_security_graph


def test_security_graph_connects_scan_finding_endpoint_and_references():
    graph = build_security_graph(
        scans=[
            {
                "scan_id": "scan-1",
                "project_name": "demo",
                "scan_type": "github",
                "status": "COMPLETED",
            }
        ],
        findings=[
            {
                "id": "finding-1",
                "scan_id": "scan-1",
                "status": "open",
                "representative_finding": {
                    "finding": {
                        "message": "SQL injection",
                        "severity": "HIGH",
                        "cwe": ["CWE-89"],
                        "path": "app.py",
                        "line": 12,
                    },
                    "risk": {"risk_score": 8.5},
                    "endpoint": {
                        "method": "GET",
                        "endpoint": "/users/{id}",
                        "framework": "FastAPI",
                    },
                },
            }
        ],
    )

    node_types = {node["type"] for node in graph["nodes"]}
    edge_types = {edge["type"] for edge in graph["edges"]}

    assert node_types == {"scan", "finding", "endpoint", "cwe"}
    assert edge_types == {"contains", "affects", "mapped_to"}
    assert graph["summary"]["attack_path_candidates"] == 1
    assert graph["attack_paths"][0]["risk_score"] == 8.5


def test_security_graph_deduplicates_shared_endpoint_nodes():
    endpoint = {"method": "GET", "endpoint": "/health", "framework": "FastAPI"}
    findings = [
        {"id": "f-1", "scan_id": "s-1", "finding": {}, "endpoint": endpoint},
        {"id": "f-2", "scan_id": "s-1", "finding": {}, "endpoint": endpoint},
    ]

    graph = build_security_graph([{"scan_id": "s-1"}], findings)

    assert sum(node["type"] == "endpoint" for node in graph["nodes"]) == 1

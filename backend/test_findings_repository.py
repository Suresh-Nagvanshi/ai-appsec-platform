import json
from pathlib import Path

from ai.batch_analysis_engine import (
    BatchAnalysisEngine
)
from storage.findings_repository import (
    FindingsRepository
)


BASE_DIR = Path(__file__).resolve().parent.parent

results_file = (
    BASE_DIR
    / "results"
    / "WebGoat_github_results.json"
)

with open(
    results_file,
    "r",
    encoding="utf-8"
) as file:

    semgrep_results = json.load(file)

findings = semgrep_results.get(
    "results",
    []
)[:5]

engine = BatchAnalysisEngine()

batch_results = engine.process_findings(
    findings=findings,
    project_path=str(
        BASE_DIR / "repos" / "WebGoat"
    ),
    max_findings=5
)

repository = FindingsRepository()

scan_id = repository.save_scan(
    project_name="WebGoat",
    scan_results=batch_results
)

print("\n===== SCAN SAVED =====\n")

print(f"Scan ID: {scan_id}")

print("\n===== STORED SCANS =====\n")

print(
    json.dumps(
        repository.list_scans(),
        indent=4
    )
)
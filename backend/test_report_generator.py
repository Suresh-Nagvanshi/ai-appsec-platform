import json
from pathlib import Path

from ai.batch_analysis_engine import (
    BatchAnalysisEngine
)
from reporting.report_generator import (
    ReportGenerator
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

scan_results = engine.process_findings(
    findings=findings,
    project_path=str(
        BASE_DIR / "repos" / "WebGoat"
    ),
    max_findings=5
)

generator = ReportGenerator()

report_path = generator.generate_json_report(
    scan_results
)

print("\n===== REPORT GENERATED =====\n")

print(f"Report Path: {report_path}")
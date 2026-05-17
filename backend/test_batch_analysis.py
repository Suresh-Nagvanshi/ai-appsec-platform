import json
from pathlib import Path

from ai.batch_analysis_engine import (
    BatchAnalysisEngine
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
)

engine = BatchAnalysisEngine()

results = engine.process_findings(
    findings=findings,
    project_path=str(
        BASE_DIR / "repos" / "WebGoat"
    ),
    max_findings=5
)

print("\n===== BATCH ANALYSIS =====\n")

print(
    json.dumps(
        results,
        indent=4
    )
)
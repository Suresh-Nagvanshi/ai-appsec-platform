import json
from pathlib import Path

from enrichment.context_builder import ContextBuilder
from risk.risk_scorer import RiskScorer


BASE_DIR = Path(__file__).resolve().parent.parent

results_file = BASE_DIR / "results" / "WebGoat_github_results.json"

with open(
    results_file,
    "r",
    encoding="utf-8"
) as file:

    semgrep_results = json.load(file)

findings = semgrep_results.get("results", [])

sample_finding = findings[0]

builder = ContextBuilder()

enriched = builder.build(
    finding=sample_finding,
    project_path=str(
        BASE_DIR / "repos" / "WebGoat"
    )
)

scorer = RiskScorer()

risk = scorer.calculate(enriched)

print("\n===== RISK ANALYSIS =====\n")

print(
    json.dumps(
        risk,
        indent=4
    )
)
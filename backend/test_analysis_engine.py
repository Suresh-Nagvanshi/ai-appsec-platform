import json
from pathlib import Path

from enrichment.context_builder import ContextBuilder
from risk.risk_scorer import RiskScorer
from ai.analysis_engine import AnalysisEngine


BASE_DIR = Path(__file__).resolve().parent.parent

results_file = BASE_DIR / "results" / "WebGoat_github_results.json"

with open(
    results_file,
    "r",
    encoding="utf-8"
) as file:

    semgrep_results = json.load(file)

finding = semgrep_results["results"][0]

builder = ContextBuilder()

enriched = builder.build(
    finding=finding,
    project_path=str(
        BASE_DIR / "repos" / "WebGoat"
    )
)

scorer = RiskScorer()

risk = scorer.calculate(
    enriched
)

enriched["risk"] = risk

engine = AnalysisEngine()

result = engine.analyze(
    enriched
)

print("\n===== AI SECURITY ANALYSIS =====\n")

print(
    json.dumps(
        result,
        indent=4
    )
)
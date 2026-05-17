import json
from pathlib import Path

from enrichment.context_builder import ContextBuilder
from risk.risk_scorer import RiskScorer
from ai.model_router import ModelRouter


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

builder = ContextBuilder()

scorer = RiskScorer()

router = ModelRouter()

print("\n===== MODEL ROUTING =====\n")

for finding in findings:

    enriched = builder.build(
        finding=finding,
        project_path=str(
            BASE_DIR / "repos" / "WebGoat"
        )
    )

    risk = scorer.calculate(
        enriched
    )

    enriched["risk"] = risk

    route = router.route(
        enriched
    )

    print(
        json.dumps(
            {
                "rule_id": enriched["finding"]["rule_id"],
                "risk_score": risk["risk_score"],
                "routing": route
            },
            indent=4
        )
    )

    print("\n" + "=" * 80 + "\n")
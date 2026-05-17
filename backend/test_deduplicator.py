import json
from pathlib import Path

from enrichment.context_builder import ContextBuilder
from risk.risk_scorer import RiskScorer
from deduplication.finding_deduplicator import FindingDeduplicator


BASE_DIR = Path(__file__).resolve().parent.parent

results_file = BASE_DIR / "results" / "WebGoat_github_results.json"

with open(
    results_file,
    "r",
    encoding="utf-8"
) as file:

    semgrep_results = json.load(file)

raw_findings = semgrep_results.get(
    "results",
    []
)[:20]

builder = ContextBuilder()

scorer = RiskScorer()

processed_findings = []

for finding in raw_findings:

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

    processed_findings.append(
        enriched
    )

deduplicator = FindingDeduplicator()

results = deduplicator.deduplicate(
    processed_findings
)

print("\n===== DEDUPLICATED FINDINGS =====\n")

print(
    json.dumps(
        results[:3],
        indent=4
    )
)

print(
    f"\nOriginal Findings: "
    f"{len(processed_findings)}"
)

print(
    f"Deduplicated Groups: "
    f"{len(results)}"
)
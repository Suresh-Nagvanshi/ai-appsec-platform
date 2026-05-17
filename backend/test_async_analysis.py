import asyncio
import json
from pathlib import Path

from enrichment.context_builder import ContextBuilder
from risk.risk_scorer import RiskScorer
from ai.async_analysis_engine import (
    AsyncAnalysisEngine
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

raw_findings = semgrep_results.get(
    "results",
    []
)[:5]

builder = ContextBuilder()

scorer = RiskScorer()

prepared_findings = []

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

    prepared_findings.append(
        enriched
    )


async def main():

    engine = AsyncAnalysisEngine()

    results = await engine.analyze_findings(
        prepared_findings
    )

    print(
        "\n===== ASYNC ANALYSIS =====\n"
    )

    print(
        json.dumps(
            results,
            indent=4
        )
    )


asyncio.run(main())
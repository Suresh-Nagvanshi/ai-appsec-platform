import json
from pathlib import Path

from enrichment.context_builder import ContextBuilder
from risk.risk_scorer import RiskScorer
from ai.prompt_builder import PromptBuilder


BASE_DIR = Path(__file__).resolve().parent.parent

results_file = BASE_DIR / "results" / "WebGoat_github_results.json"

with open(
    results_file,
    "r",
    encoding="utf-8"
) as file:

    semgrep_results = json.load(file)

finding = semgrep_results["results"][1]

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

prompt_builder = PromptBuilder()

prompt = prompt_builder.build(
    enriched
)

print("\n===== GENERATED PROMPT =====\n")

print(prompt[:5000])
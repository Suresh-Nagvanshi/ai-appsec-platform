import json
from pathlib import Path

from enrichment.context_builder import ContextBuilder


BASE_DIR = Path(__file__).resolve().parent.parent

# Load WebGoat findings
results_file = BASE_DIR / "results" / "WebGoat_github_results.json"

with open(
    results_file,
    "r",
    encoding="utf-8"
) as file:

    semgrep_results = json.load(file)

findings = semgrep_results.get("results", [])

if not findings:
    print("No findings found.")
    exit()

sample_finding = findings[0]

builder = ContextBuilder()

context = builder.build(
    finding=sample_finding,
    project_path=str(
        BASE_DIR / "repos" / "WebGoat"
    )
)

print("\n===== ENRICHED FINDING =====\n")

print(
    json.dumps(
        context,
        indent=4
    )
)
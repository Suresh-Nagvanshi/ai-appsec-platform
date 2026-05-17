import json
from pathlib import Path

from storage.findings_repository import (
    FindingsRepository
)
from storage.diff_analyzer import (
    DiffAnalyzer
)


repository = FindingsRepository()

scans = repository.list_scans()

if len(scans) < 2:

    print(
        "\nNeed at least 2 scans "
        "to perform diff analysis."
    )

    exit()

latest_scan_id = scans[0]["scan_id"]

previous_scan_id = scans[1]["scan_id"]

latest_scan = repository.get_scan(
    latest_scan_id
)

previous_scan = repository.get_scan(
    previous_scan_id
)

analyzer = DiffAnalyzer()

diff = analyzer.compare_scans(
    old_scan=previous_scan,
    new_scan=latest_scan
)

print("\n===== DIFF ANALYSIS =====\n")

print(
    json.dumps(
        diff["summary"],
        indent=4
    )
)

print(
    f"\nNew Findings: "
    f"{len(diff['new_findings'])}"
)

print(
    f"Resolved Findings: "
    f"{len(diff['resolved_findings'])}"
)

print(
    f"Persistent Findings: "
    f"{len(diff['persistent_findings'])}"
)
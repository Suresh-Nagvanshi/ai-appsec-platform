import json

SEMGRP_FILE = "data/semgrep/parsed_results.json"
MITRE_FILE = "data/mitre/mitre_techniques.json"
FIXES_FILE = "data/cvefixes/cve_fixes.json"

OUTPUT_FILE = "data/correlation_output.json"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def match_mitre(vulnerability_text, mitre_data):
    keywords = vulnerability_text.lower()

    matches = []
    for item in mitre_data:
        name = item["name"].lower()
        desc = item["description"].lower()

        if any(word in keywords for word in name.split()):
            matches.append(item)
        elif any(word in keywords for word in desc.split()):
            matches.append(item)

    return matches[:2]  # limit results


def match_fixes(vulnerability_text, fixes_data):
    keywords = vulnerability_text.lower()

    matches = []
    for item in fixes_data:
        vuln = item["vulnerability"].lower()

        if any(word in keywords for word in vuln.split()):
            matches.append(item)

    return matches[:1]  # best match only


def correlate():
    semgrep = load_json(SEMGRP_FILE)
    mitre = load_json(MITRE_FILE)
    fixes = load_json(FIXES_FILE)

    output = []

    for finding in semgrep:
        vuln_text = finding.get("vulnerability", "")

        correlated = {
            "file": finding["file"],
            "line": finding["line"],
            "issue": vuln_text,
            "severity": finding["severity"],
            "cwe": finding["cwe"],

            "mitre_matches": match_mitre(vuln_text, mitre),
            "fixes": match_fixes(vuln_text, fixes)
        }

        output.append(correlated)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)

    print(f"✅ Correlation complete → {OUTPUT_FILE}")


if __name__ == "__main__":
    correlate()
import json

INPUT_FILE = "data/semgrep/output.json"
OUTPUT_FILE = "data/semgrep/parsed_results.json"

def parse_semgrep():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    parsed = []

    for item in results:
        parsed_item = {
            "file": item.get("path"),
            "line": item.get("start", {}).get("line"),
            "vulnerability": item.get("extra", {}).get("message"),
            "severity": item.get("extra", {}).get("severity"),
            "cwe": item.get("extra", {}).get("metadata", {}).get("cwe"),
            "owasp": item.get("extra", {}).get("metadata", {}).get("owasp"),
            "technology": item.get("extra", {}).get("metadata", {}).get("technology")
        }
        parsed.append(parsed_item)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=4)

    print(f"✅ Parsed {len(parsed)} findings → saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    parse_semgrep()
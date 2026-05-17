import json
import os


# Get the directory of the current script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Input file (your NVD file)
INPUT_FILE = os.path.join(BASE_DIR, "nvdcve-2.0-recent.json")

# Output file
OUTPUT_FILE = os.path.join(BASE_DIR, "sample_cves.json")


# Keywords to filter relevant vulnerabilities
KEYWORDS = [
    "sql injection",
    "xss",
    "cross site scripting",
    "authentication",
    "authorization",
    "misconfiguration",
    "csrf",
    "server-side request forgery",
    "ssrf"
]

def extract_cves():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        # CVE ID
        cve_id = cve.get("id", "N/A")

        # Description
        description_data = cve.get("descriptions", [])
        description = ""
        for desc in description_data:
            if desc.get("lang") == "en":
                description = desc.get("value", "").lower()
                break

        # Filter based on keywords
        if not any(keyword in description for keyword in KEYWORDS):
            continue

        # Severity & Attack Vector
        severity = "N/A"
        attack_vector = "N/A"

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
        else:
            cvss = {}

        severity = cvss.get("baseSeverity", "N/A")
        attack_vector = cvss.get("attackVector", "N/A")

        # Add to result
        results.append({
            "id": cve_id,
            "description": description,
            "severity": severity,
            "attack_vector": attack_vector
        })

        # Limit to ~25 entries
        if len(results) >= 25:
            break

    # Save output
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print(f"Extracted {len(results)} CVEs and saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    extract_cves()
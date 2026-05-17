import json
import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq

# Load .env
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Initialize Groq LLM
llm = ChatGroq(
    temperature=0.3,
    groq_api_key=GROQ_API_KEY,
    model_name="llama-3.1-8b-instant"
)

# Load correlated findings
with open("data/correlation_output.json", "r", encoding="utf-8") as f:
    findings = json.load(f)

ai_reports = []

# Limit findings initially (avoid huge API usage)
MAX_FINDINGS = 5

for finding in findings[:MAX_FINDINGS]:

    vulnerability_text = finding.get("issue", "")
    severity = finding.get("severity", "")
    cwe = ", ".join(finding.get("cwe", []))

    mitre = finding.get("mitre_matches", [])
    fixes = finding.get("fixes", [])

    mitre_text = ""
    if mitre:
        mitre_text = f"""
MITRE Techniques:
{json.dumps(mitre, indent=2)}
"""

    fix_text = ""
    if fixes:
        fix_text = f"""
Known Fixes:
{json.dumps(fixes, indent=2)}
"""

    prompt = f"""
You are an expert Application Security Engineer.

Analyze this vulnerability finding.

Vulnerability:
{vulnerability_text}

Severity:
{severity}

CWE:
{cwe}

{mitre_text}

{fix_text}

Provide:
1. Vulnerability summary
2. Why it is dangerous
3. Real-world impact
4. Secure remediation guidance
5. Developer-friendly fix recommendation
6. Risk rating explanation
"""

    try:
        response = llm.invoke(prompt)

        ai_reports.append({
            "file": finding.get("file"),
            "line": finding.get("line"),
            "severity": severity,
            "cwe": finding.get("cwe"),
            "ai_explanation": response.content
        })

        print(f"Processed: {finding.get('file')}")

    except Exception as e:
        print(f"Error processing finding: {e}")

# Save final AI report
with open("data/ai_report.json", "w", encoding="utf-8") as f:
    json.dump(ai_reports, f, indent=4)

print("\nAI Security Report Generated Successfully!")
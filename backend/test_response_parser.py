from ai.response_parser import ResponseParser


fake_response = """
```json
{
  "summary": "Possible SQL injection vulnerability.",
  "vulnerability_type": "SQL Injection",
  "exploitability": "High",
  "attack_scenario": "Attacker injects SQL payloads.",
  "business_impact": "Database compromise.",
  "false_positive_probability": "Low",
  "confidence_reasoning": "Direct string concatenation detected.",
  "secure_fix": "Use PreparedStatement.",
  "developer_remediation_steps": [
    "Use parameterized queries",
    "Validate input"
  ],
  "mitre_attack_mapping": [
    "T1190"
  ],
  "references": [
    "https://owasp.org/www-community/attacks/SQL_Injection"
  ]
}

"""

parser = ResponseParser()

parsed = parser.parse(
fake_response
)

print("\n===== PARSED AI RESPONSE =====\n")

print(parsed)
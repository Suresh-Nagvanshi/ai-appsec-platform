import json
from typing import Dict


class PromptBuilder:
    """
    Builds structured AppSec reasoning prompts
    for LLM analysis.
    """

    SYSTEM_PROMPT = """
You are an elite Application Security (AppSec) expert.

Your job is to analyze security findings with:
- exploitability reasoning
- contextual understanding
- realistic impact analysis
- false-positive awareness
- secure remediation guidance

You MUST:
- think like a senior security engineer
- avoid hallucinations
- use provided context carefully
- prioritize realistic exploitability
- provide concise but accurate reasoning

Always return valid JSON only.
"""

    def build(
        self,
        enriched_finding: Dict
    ) -> str:
        """
        Build structured AI analysis prompt.
        """

        finding = enriched_finding.get(
            "finding",
            {}
        )

        framework = enriched_finding.get(
            "framework",
            {}
        )

        endpoint = enriched_finding.get(
            "endpoint"
        )

        snippet = enriched_finding.get(
            "snippet",
            {}
        )

        metadata = enriched_finding.get(
            "metadata",
            {}
        )

        risk = enriched_finding.get(
            "risk",
            {}
        )

        structured_context = {
            "finding": {
                "rule_id": finding.get(
                    "rule_id"
                ),

                "severity": finding.get(
                    "severity"
                ),

                "message": finding.get(
                    "message"
                ),

                "cwe": finding.get(
                    "cwe"
                ),

                "owasp": finding.get(
                    "owasp"
                )
            },

            "risk_analysis": risk,

            "technology_context": {
                "language": metadata.get(
                    "language"
                ),

                "framework": framework.get(
                    "primary_framework"
                ),

                "detected_frameworks": framework.get(
                    "detected_frameworks"
                )
            },

            "endpoint_context": endpoint,

            "source_code": {
                "vulnerable_line": snippet.get(
                    "vulnerable_line"
                ),

                "before_context": snippet.get(
                    "before_context"
                ),

                "after_context": snippet.get(
                    "after_context"
                )
            }
        }

        instructions = """
Analyze this vulnerability deeply.

Return STRICT JSON in this format:

{
  "summary": "",
  "vulnerability_type": "",
  "exploitability": "",
  "attack_scenario": "",
  "business_impact": "",
  "false_positive_probability": "",
  "confidence_reasoning": "",
  "secure_fix": "",
  "developer_remediation_steps": [],
  "mitre_attack_mapping": [],
  "references": []
}

Rules:
- Be concise but accurate
- Avoid generic explanations
- Focus on realistic exploitation
- Use provided code context
- Mention if exploitability appears limited
- Mention if finding appears likely valid
- Do NOT return markdown
- Do NOT return explanations outside JSON
"""

        final_prompt = (
            self.SYSTEM_PROMPT
            + "\n\n"
            + "SECURITY FINDING CONTEXT:\n"
            + json.dumps(
                structured_context,
                indent=2
            )
            + "\n\n"
            + instructions
        )

        return final_prompt
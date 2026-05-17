import json
from datetime import datetime
from pathlib import Path
from typing import Dict


class ReportGenerator:
    """
    Security report generation engine.

    Responsibilities:
    - executive summaries
    - technical findings
    - AI reasoning output
    - posture summaries
    - risk aggregation

    Initial format:
    - JSON

    Future upgrades:
    - PDF export
    - HTML dashboards
    - Markdown reports
    - SARIF export
    """

    def generate_json_report(
        self,
        scan_data: Dict,
        output_dir: str = "reports"
    ) -> str:
        """
        Generate structured JSON report.
        """

        Path(output_dir).mkdir(
            parents=True,
            exist_ok=True
        )

        timestamp = datetime.utcnow().strftime(
            "%Y%m%d_%H%M%S"
        )

        report_name = (
            f"security_report_{timestamp}.json"
        )

        report_path = (
            Path(output_dir)
            / report_name
        )

        report = {

            "report_metadata": {
                "generated_at":
                    datetime.utcnow().isoformat(),

                "report_version": "1.0",

                "generator":
                    "AI Security Agent"
            },

            "executive_summary":
                self._build_executive_summary(
                    scan_data
                ),

            "risk_summary":
                scan_data.get(
                    "summary",
                    {}
                ),

            "scan_metadata":
                scan_data.get(
                    "metadata",
                    {}
                ),

            "findings":
                self._build_findings_section(
                    scan_data
                )
        }

        with open(
            report_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4
            )

        return str(report_path)

    def _build_executive_summary(
        self,
        scan_data: Dict
    ) -> Dict:
        """
        Build high-level security summary.
        """

        summary = scan_data.get(
            "summary",
            {}
        )

        metadata = scan_data.get(
            "metadata",
            {}
        )

        top_risk = summary.get(
            "top_risk_score",
            0
        )

        posture = (
            "Critical"
            if top_risk >= 9
            else
            "High"
            if top_risk >= 7
            else
            "Moderate"
            if top_risk >= 4
            else
            "Low"
        )

        return {

            "security_posture":
                posture,

            "top_risk_score":
                top_risk,

            "total_findings":
                metadata.get(
                    "raw_findings",
                    0
                ),

            "deduplicated_findings":
                metadata.get(
                    "deduplicated_groups",
                    0
                ),

            "successful_ai_analyses":
                metadata.get(
                    "successful_analyses",
                    0
                )
        }

    def _build_findings_section(
        self,
        scan_data: Dict
    ) -> list:
        """
        Build detailed findings section.
        """

        results = scan_data.get(
            "results",
            []
        )

        findings_output = []

        for item in results:

            finding = item.get(
                "finding",
                {}
            )

            ai = item.get(
                "ai_analysis",
                {}
            )

            risk = item.get(
                "risk",
                {}
            )

            findings_output.append({

                "finding_metadata": {

                    "rule_id":
                        finding.get(
                            "rule_id"
                        ),

                    "severity":
                        finding.get(
                            "severity"
                        ),

                    "path":
                        finding.get(
                            "path"
                        ),

                    "message":
                        finding.get(
                            "message"
                        ),

                    "cwe":
                        finding.get(
                            "cwe",
                            []
                        ),

                    "owasp":
                        finding.get(
                            "owasp",
                            []
                        )
                },

                "risk_analysis": {

                    "risk_score":
                        risk.get(
                            "risk_score"
                        ),

                    "priority":
                        risk.get(
                            "priority"
                        ),

                    "exploitability":
                        risk.get(
                            "exploitability"
                        ),

                    "confidence":
                        risk.get(
                            "confidence"
                        )
                },

                "ai_analysis": {

                    "summary":
                        ai.get(
                            "summary"
                        ),

                    "attack_scenario":
                        ai.get(
                            "attack_scenario"
                        ),

                    "business_impact":
                        ai.get(
                            "business_impact"
                        ),

                    "secure_fix":
                        ai.get(
                            "secure_fix"
                        ),

                    "developer_remediation_steps":
                        ai.get(
                            "developer_remediation_steps",
                            []
                        ),

                    "false_positive_probability":
                        ai.get(
                            "false_positive_probability"
                        )
                }
            })

        return findings_output
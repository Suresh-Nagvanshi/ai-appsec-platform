import json
from datetime import datetime, timezone
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

    def generate(self, project_name: str, findings: list) -> Dict:
        scan_data = {
            "summary": {"top_risk_score": 8.5},
            "metadata": {"raw_findings": len(findings), "deduplicated_groups": len(findings)},
            "results": findings
        }
        return {
            "project_name": project_name,
            "executive_summary": self._build_executive_summary(scan_data),
            "findings": self._build_findings_section(scan_data)
        }

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

    def generate_markdown_report(self, scan_data: Dict) -> str:
        project = scan_data.get("project_name", "Security Scan")
        findings = scan_data.get("findings", [])
        summary = scan_data.get("summary", {})

        md = [
            f"# Executive Security Report — {project}",
            f"**Scan ID:** `{scan_data.get('scan_id', 'N/A')}`  ",
            f"**Generated:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}`  \n",
            "## 1. Executive Summary",
            f"- **Total Findings:** {len(findings)}",
            f"- **Top Risk Score:** {summary.get('top_risk_score', 'N/A')}",
            f"- **Critical:** {summary.get('critical', 0)} | **High:** {summary.get('high', 0)} | **Medium:** {summary.get('medium', 0)} | **Low:** {summary.get('low', 0)}\n",
            "## 2. Security Findings\n",
        ]

        for i, f in enumerate(findings, 1):
            rule = f.get("rule_id") or f.get("title") or "Finding"
            sev = f.get("severity", "UNKNOWN")
            path = f.get("path") or f.get("filePath") or "N/A"
            line = f.get("line", "N/A")
            msg = f.get("message", "N/A")
            ai = f.get("ai_analysis") or {}

            md.append(f"### {i}. [{sev}] {rule}")
            md.append(f"- **Location:** `{path}:{line}`")
            md.append(f"- **Message:** {msg}")
            if ai.get("summary"):
                md.append(f"- **AI Analysis:** {ai.get('summary')}")
            if ai.get("secure_fix"):
                md.append(f"- **Remediation:** {ai.get('secure_fix')}")
            md.append("")

        return "\n".join(md)

    def generate_html_report(self, scan_data: Dict) -> str:
        project = scan_data.get("project_name", "Security Scan")
        findings = scan_data.get("findings", [])
        summary = scan_data.get("summary", {})

        rows = []
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            rule = f.get("rule_id") or f.get("title") or "Finding"
            path = f.get("path") or f.get("filePath") or "N/A"
            line = f.get("line", "-")
            msg = f.get("message", "-")
            
            badge_color = "#ef4444" if sev in ("CRITICAL", "ERROR") else "#f97316" if sev == "HIGH" else "#eab308" if sev == "MEDIUM" else "#3b82f6"
            rows.append(f"""
            <tr>
                <td><span style="background:{badge_color}; color:#fff; padding:2px 8px; border-radius:4px; font-weight:bold; font-size:12px;">{sev}</span></td>
                <td><strong>{rule}</strong></td>
                <td><code>{path}:{line}</code></td>
                <td>{msg}</td>
            </tr>
            """)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Report - {project}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #09090b; color: #f4f4f5; }}
        h1 {{ border-bottom: 2px solid #27272a; padding-bottom: 12px; font-size: 24px; }}
        .card {{ background: #18181b; border: 1px solid #27272a; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #27272a; font-size: 14px; }}
        th {{ background: #27272a; color: #a1a1aa; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report — {project}</h1>
    <div class="card">
        <h3>Executive Summary</h3>
        <p>Total Findings: <strong>{len(findings)}</strong> | Top Risk Score: <strong>{summary.get('top_risk_score', 'N/A')}</strong></p>
    </div>
    <div class="card">
        <h3>Detailed Vulnerabilities</h3>
        <table>
            <thead>
                <tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th></tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
</body>
</html>"""
        return html
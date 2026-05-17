import time
from typing import Dict, List

from enrichment.context_builder import ContextBuilder
from risk.risk_scorer import RiskScorer
from deduplication.finding_deduplicator import (
    FindingDeduplicator
)
from ai.analysis_engine import AnalysisEngine


class BatchAnalysisEngine:
    """
    Scalable orchestration engine for
    bulk security finding analysis.

    Responsibilities:
    - enrichment
    - risk scoring
    - deduplication
    - AI reasoning
    - aggregation

    Future upgrades:
    - async workers
    - queue systems
    - parallel execution
    - model routing
    - fallback providers
    """

    def __init__(self):

        self.context_builder = ContextBuilder()

        self.risk_scorer = RiskScorer()

        self.deduplicator = FindingDeduplicator()

        self.analysis_engine = AnalysisEngine()

    def process_findings(
        self,
        findings: List[Dict],
        project_path: str,
        max_findings: int = 20
    ) -> Dict:
        """
        Process security findings pipeline.

        Args:
            findings: Raw Semgrep findings
            project_path: Repository/project path
            max_findings: Safety cap for AI analysis

        Returns:
            Aggregated analysis results
        """

        start_time = time.time()

        # =========================
        # Safety Limit
        # =========================

        findings = findings[:max_findings]

        # =========================
        # Enrichment Phase
        # =========================

        enriched_findings = []

        for finding in findings:

            try:

                enriched = self.context_builder.build(
                    finding=finding,
                    project_path=project_path
                )

                risk = self.risk_scorer.calculate(
                    enriched
                )

                enriched["risk"] = risk

                enriched_findings.append(
                    enriched
                )

            except Exception as error:

                print(
                    f"[ENRICHMENT ERROR] {error}"
                )

        # =========================
        # Deduplication Phase
        # =========================

        deduplicated = self.deduplicator.deduplicate(
            enriched_findings
        )

        # =========================
        # AI Analysis Phase
        # =========================

        analyzed_results = []

        for group in deduplicated:

            try:

                representative = group[
                    "representative_finding"
                ]

                ai_analysis = (
                    self.analysis_engine.analyze(
                        representative
                    )
                )

                analyzed_results.append({

                    "group_metadata": {
                        "deduplication_key": group[
                            "deduplication_key"
                        ],

                        "total_occurrences": group[
                            "total_occurrences"
                        ]
                    },

                    "risk_summary": group[
                        "risk_summary"
                    ],

                    # IMPORTANT
                    "finding": representative.get(
                        "finding",
                        {}
                    ),

                    "snippet": representative.get(
                        "snippet",
                        {}
                    ),

                    "endpoint": representative.get(
                        "endpoint"
                    ),

                    "framework": representative.get(
                        "framework",
                        {}
                    ),

                    "risk": representative.get(
                        "risk",
                        {}
                    ),

                    "ai_analysis": ai_analysis
                })

            except Exception as error:

                analyzed_results.append({

                    "group_metadata": {
                        "deduplication_key": group.get(
                            "deduplication_key"
                        ),

                        "analysis_failed": True
                    },

                    "error": str(error)
                })

        # =========================
        # Final Summary
        # =========================

        duration = round(
            time.time() - start_time,
            2
        )

        summary = self._build_summary(
            analyzed_results
        )

        return {

            "summary": summary,

            "metadata": {
                "raw_findings": len(findings),

                "deduplicated_groups": len(
                    deduplicated
                ),

                "successful_analyses": len([
                    item for item in analyzed_results
                    if "ai_analysis" in item
                ]),

                "duration_seconds": duration
            },

            "results": analyzed_results
        }

    def _build_summary(
        self,
        analyzed_results: List[Dict]
    ) -> Dict:
        """
        Build high-level security summary.
        """

        priorities = {
            "P1": 0,
            "P2": 0,
            "P3": 0,
            "P4": 0
        }

        exploitability = {
            "Very High": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }

        top_risk_score = 0

        for result in analyzed_results:

            risk = result.get(
                "risk_summary",
                {}
            )

            priority = risk.get(
                "highest_priority"
            )

            if priority in priorities:
                priorities[priority] += 1

            max_risk = risk.get(
                "max_risk_score",
                0
            )

            top_risk_score = max(
                top_risk_score,
                max_risk
            )

            ai = result.get(
                "ai_analysis",
                {}
            )

            level = ai.get(
                "exploitability"
            )

            if level in exploitability:
                exploitability[level] += 1

        return {

            "top_risk_score": top_risk_score,

            "priority_distribution": priorities,

            "exploitability_distribution":
                exploitability
        }
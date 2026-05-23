from backend.enrichment.context_builder import ContextBuilder
from backend.risk.risk_scorer import RiskScorer
from backend.deduplication.finding_deduplicator import (
    FindingDeduplicator
)
from backend.ai.analysis_engine import AnalysisEngine


class BatchAnalysisEngine:
    """
    Runs the full enrichment + analysis pipeline
    over a list of raw Semgrep findings.

    Intended for use outside the orchestrator
    (e.g. re-analysis jobs, report regeneration).
    """

    def __init__(self, model_name: str = None):
        self.context_builder = ContextBuilder()
        self.risk_scorer = RiskScorer()
        self.deduplicator = FindingDeduplicator()
        self.model_name = model_name

    def run(
        self,
        raw_findings: list,
        project_path: str,
        project_name: str,
    ) -> list:
        """
        Process a list of raw Semgrep findings through
        the full pipeline and return enriched results.
        """
        enriched_list = []

        for raw in raw_findings:
            try:
                enriched = self.context_builder.build(
                    finding=raw,
                    project_path=project_path,
                )
                risk = self.risk_scorer.calculate(enriched)
                enriched["risk"] = risk

                engine = AnalysisEngine(
                    model_name=self.model_name
                ) if self.model_name else AnalysisEngine()

                ai_result = engine.analyze(enriched)
                enriched["ai_analysis"] = ai_result

                enriched_list.append(enriched)

            except Exception as exc:
                enriched_list.append({
                    "finding": raw,
                    "risk": {},
                    "ai_analysis": {"error": str(exc)},
                })

        return self.deduplicator.deduplicate(enriched_list)

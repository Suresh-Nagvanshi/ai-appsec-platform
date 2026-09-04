from backend.enrichment.context_builder import ContextBuilder
from backend.risk.risk_scorer import RiskScorer
from backend.ai.analysis_engine import AnalysisEngine

def test_analysis_engine(sample_semgrep_finding, sample_project_dir):
    builder = ContextBuilder()
    enriched = builder.build(finding=sample_semgrep_finding, project_path=str(sample_project_dir))
    scorer = RiskScorer()
    enriched["risk"] = scorer.calculate(enriched)
    
    engine = AnalysisEngine()
    result = engine.analyze(enriched)
    assert result is not None
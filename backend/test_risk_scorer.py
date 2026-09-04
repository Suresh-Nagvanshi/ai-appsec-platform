from backend.enrichment.context_builder import ContextBuilder
from backend.risk.risk_scorer import RiskScorer

def test_risk_scorer(sample_semgrep_finding, sample_project_dir):
    builder = ContextBuilder()
    enriched = builder.build(
        finding=sample_semgrep_finding,
        project_path=str(sample_project_dir)
    )
    scorer = RiskScorer()
    risk = scorer.calculate(enriched)
    
    assert risk is not None
    assert "risk_score" in risk
    assert "severity" in risk
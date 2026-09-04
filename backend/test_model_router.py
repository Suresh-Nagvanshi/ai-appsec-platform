from backend.enrichment.context_builder import ContextBuilder
from backend.risk.risk_scorer import RiskScorer
from backend.ai.model_router import ModelRouter

def test_model_router(sample_semgrep_finding, sample_project_dir):
    builder = ContextBuilder()
    enriched = builder.build(
        finding=sample_semgrep_finding,
        project_path=str(sample_project_dir)
    )
    scorer = RiskScorer()
    enriched["risk"] = scorer.calculate(enriched)
    
    router = ModelRouter()
    route = router.route(enriched)
    
    assert route is not None
    assert "selected_model" in route
import pytest
from backend.enrichment.context_builder import ContextBuilder
from backend.risk.risk_scorer import RiskScorer
from backend.ai.async_analysis_engine import AsyncAnalysisEngine

@pytest.mark.anyio
async def test_async_analysis_engine(sample_semgrep_finding, sample_project_dir):
    builder = ContextBuilder()
    enriched = builder.build(finding=sample_semgrep_finding, project_path=str(sample_project_dir))
    scorer = RiskScorer()
    enriched["risk"] = scorer.calculate(enriched)
    
    engine = AsyncAnalysisEngine()
    results = await engine.analyze_batch([enriched])
    assert len(results) == 1
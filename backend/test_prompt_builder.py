from backend.enrichment.context_builder import ContextBuilder
from backend.risk.risk_scorer import RiskScorer
from backend.ai.prompt_builder import PromptBuilder

def test_prompt_builder(sample_semgrep_finding, sample_project_dir):
    builder = ContextBuilder()
    enriched = builder.build(finding=sample_semgrep_finding, project_path=str(sample_project_dir))
    scorer = RiskScorer()
    enriched["risk"] = scorer.calculate(enriched)
    
    prompt = PromptBuilder().build(enriched)
    assert prompt is not None
    assert len(prompt) > 0
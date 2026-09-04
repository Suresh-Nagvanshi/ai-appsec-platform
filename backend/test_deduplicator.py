from backend.enrichment.context_builder import ContextBuilder
from backend.risk.risk_scorer import RiskScorer
from backend.deduplication.finding_deduplicator import FindingDeduplicator

def test_deduplicator(sample_semgrep_finding, sample_project_dir):
    builder = ContextBuilder()
    scorer = RiskScorer()
    
    enriched = builder.build(
        finding=sample_semgrep_finding,
        project_path=str(sample_project_dir)
    )
    enriched["risk"] = scorer.calculate(enriched)
    
    deduplicator = FindingDeduplicator()
    results = deduplicator.deduplicate([enriched, enriched])
    
    assert results is not None
    assert len(results) >= 1
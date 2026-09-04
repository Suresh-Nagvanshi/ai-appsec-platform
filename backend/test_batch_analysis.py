from backend.ai.batch_analysis_engine import BatchAnalysisEngine

def test_batch_analysis_engine(sample_semgrep_results, sample_project_dir):
    engine = BatchAnalysisEngine()
    findings = sample_semgrep_results.get("results", [])
    batch_results = engine.process_findings(
        findings=findings,
        project_path=str(sample_project_dir),
        max_findings=5
    )
    assert batch_results is not None
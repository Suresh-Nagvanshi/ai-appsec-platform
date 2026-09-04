from backend.enrichment.context_builder import ContextBuilder

def test_context_builder(sample_semgrep_finding, sample_project_dir):
    builder = ContextBuilder()
    context = builder.build(
        finding=sample_semgrep_finding,
        project_path=str(sample_project_dir)
    )
    assert context is not None
    assert "finding" in context
    assert "framework" in context
    assert "snippet" in context
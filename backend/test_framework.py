from backend.enrichment.framework_detector import FrameworkDetector

def test_framework_detector(sample_project_dir):
    detector = FrameworkDetector()
    result = detector.detect(str(sample_project_dir))
    assert result is not None
    assert "primary_framework" in result
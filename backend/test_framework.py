from pathlib import Path

from enrichment.framework_detector import FrameworkDetector


BASE_DIR = Path(__file__).resolve().parent.parent

# Change project if needed
project_path = BASE_DIR / "repos" / "WebGoat"

detector = FrameworkDetector()

result = detector.detect(str(project_path))

print("\n===== FRAMEWORK DETECTION RESULT =====\n")

print(result)
from pathlib import Path
import pytest

from enrichment.snippet_extractor import SnippetExtractor

BASE_DIR = Path(__file__).resolve().parent.parent

target_file = BASE_DIR / "repos" / "WebGoat"

# Find any Java file automatically
java_files = list(target_file.rglob("*.java"))

def test_snippet_extraction():
    if not java_files:
        pytest.skip("No Java files found in the fixture repository")

    sample_file = java_files[0]
    result = SnippetExtractor().extract(str(sample_file), 10)
    assert result is not None
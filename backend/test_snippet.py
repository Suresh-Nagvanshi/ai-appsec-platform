from pathlib import Path

from enrichment.snippet_extractor import SnippetExtractor

BASE_DIR = Path(__file__).resolve().parent.parent

target_file = BASE_DIR / "repos" / "WebGoat"

# Find any Java file automatically
java_files = list(target_file.rglob("*.java"))

if not java_files:
    print("No Java files found.")
    exit()

sample_file = java_files[0]

print(f"Testing file: {sample_file}")

extractor = SnippetExtractor()

result = extractor.extract(
    str(sample_file),
    10
)

print(result)
from pathlib import Path

from enrichment.endpoint_extractor import EndpointExtractor

BASE_DIR = Path(__file__).resolve().parent.parent

project_path = BASE_DIR / "repos" / "WebGoat"

extractor = EndpointExtractor()

results = extractor.extract(str(project_path))

print("\n===== EXTRACTED ENDPOINTS =====\n")

for endpoint in results[:20]:
    print(endpoint)

print(f"\nTotal endpoints found: {len(results)}")
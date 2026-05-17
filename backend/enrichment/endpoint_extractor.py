import re
from pathlib import Path
from typing import Dict, List


class EndpointExtractor:
    """
    Extracts API endpoints from supported frameworks.

    Currently supports:
    - Spring Boot
    - Express.js
    - FastAPI
    """

    SPRING_PATTERNS = [
        (
            r'@GetMapping\("([^"]+)"\)',
            "GET"
        ),
        (
            r'@PostMapping\("([^"]+)"\)',
            "POST"
        ),
        (
            r'@PutMapping\("([^"]+)"\)',
            "PUT"
        ),
        (
            r'@DeleteMapping\("([^"]+)"\)',
            "DELETE"
        ),
        (
            r'@RequestMapping\("([^"]+)"\)',
            "REQUEST"
        )
    ]

    EXPRESS_PATTERNS = [
        (
            r'app\.get\("([^"]+)"',
            "GET"
        ),
        (
            r'app\.post\("([^"]+)"',
            "POST"
        ),
        (
            r'app\.put\("([^"]+)"',
            "PUT"
        ),
        (
            r'app\.delete\("([^"]+)"',
            "DELETE"
        ),
        (
            r'router\.get\("([^"]+)"',
            "GET"
        ),
        (
            r'router\.post\("([^"]+)"',
            "POST"
        )
    ]

    FASTAPI_PATTERNS = [
        (
            r'@app\.get\("([^"]+)"\)',
            "GET"
        ),
        (
            r'@app\.post\("([^"]+)"\)',
            "POST"
        ),
        (
            r'@app\.put\("([^"]+)"\)',
            "PUT"
        ),
        (
            r'@app\.delete\("([^"]+)"\)',
            "DELETE"
        )
    ]

    def extract(self, project_path: str) -> List[Dict]:
        """
        Extract endpoints from project.

        Returns:
        [
            {
                "framework": "",
                "method": "",
                "endpoint": "",
                "file": ""
            }
        ]
        """

        project = Path(project_path)

        if not project.exists():
            return []

        endpoints = []

        # Java / Spring Boot
        java_files = list(project.rglob("*.java"))

        for java_file in java_files:

            endpoints.extend(
                self._extract_from_file(
                    java_file,
                    self.SPRING_PATTERNS,
                    "Spring Boot"
                )
            )

        # JavaScript / Express
        js_files = list(project.rglob("*.js"))

        for js_file in js_files:

            endpoints.extend(
                self._extract_from_file(
                    js_file,
                    self.EXPRESS_PATTERNS,
                    "Express.js"
                )
            )

        # Python / FastAPI
        py_files = list(project.rglob("*.py"))

        for py_file in py_files:

            endpoints.extend(
                self._extract_from_file(
                    py_file,
                    self.FASTAPI_PATTERNS,
                    "FastAPI"
                )
            )

        return endpoints

    def _extract_from_file(
        self,
        file_path: Path,
        patterns: List,
        framework: str
    ) -> List[Dict]:

        discovered = []

        try:
            with open(
                file_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:

                content = file.read()

            for pattern, method in patterns:

                matches = re.findall(pattern, content)

                for endpoint in matches:

                    discovered.append({
                        "framework": framework,
                        "method": method,
                        "endpoint": endpoint,
                        "file": str(file_path)
                    })

        except Exception:
            pass

        return discovered
from pathlib import Path
from typing import Dict, Optional

from enrichment.snippet_extractor import SnippetExtractor
from enrichment.framework_detector import FrameworkDetector
from enrichment.endpoint_extractor import EndpointExtractor


class ContextBuilder:
    """
    Builds enriched security context for findings.

    This is the orchestration layer that combines:
    - framework intelligence
    - endpoint discovery
    - vulnerable code snippets
    - surrounding context
    """

    def __init__(self):

        self.snippet_extractor = SnippetExtractor()

        self.framework_detector = FrameworkDetector()

        self.endpoint_extractor = EndpointExtractor()

    def build(
        self,
        finding: Dict,
        project_path: str
    ) -> Dict:
        """
        Build enriched finding context.

        Args:
            finding (dict): Raw Semgrep finding
            project_path (str): Root project path

        Returns:
            dict: Enriched security finding
        """

        try:

            # =========================
            # Normalize Base Finding
            # =========================

            normalized = self._normalize_finding(
                finding
            )

            file_path = normalized["path"]

            line_number = normalized["line"]

            # =========================
            # Framework Detection
            # =========================

            framework_data = self.framework_detector.detect(
                project_path
            )

            # =========================
            # Code Snippet Extraction
            # =========================

            snippet_data = self.snippet_extractor.extract(
                file_path=file_path,
                line_number=line_number
            )

            # =========================
            # Endpoint Extraction
            # =========================

            endpoints = self.endpoint_extractor.extract(
                project_path
            )

            related_endpoint = self._find_related_endpoint(
                file_path=file_path,
                endpoints=endpoints
            )

            # =========================
            # Build Final Context
            # =========================

            enriched_finding = {
                "finding": normalized,

                "framework": framework_data,

                "endpoint": related_endpoint,

                "snippet": snippet_data,

                "metadata": {
                    "language": self._detect_language(
                        file_path
                    ),

                    "project_path": str(
                        Path(project_path).resolve()
                    )
                }
            }

            return enriched_finding

        except Exception as error:

            return {
                "error": str(error)
            }

    def _normalize_finding(
        self,
        finding: Dict
    ) -> Dict:
        """
        Normalize raw Semgrep finding into
        internal platform schema.
        """

        return {
            "scanner": "semgrep",

            "rule_id": finding.get(
                "check_id"
            ),

            "severity": finding.get(
                "extra",
                {}
            ).get(
                "severity"
            ),

            "message": finding.get(
                "extra",
                {}
            ).get(
                "message"
            ),

            "path": finding.get(
                "path"
            ),

            "line": finding.get(
                "start",
                {}
            ).get(
                "line",
                1
            ),

            "cwe": finding.get(
                "extra",
                {}
            ).get(
                "metadata",
                {}
            ).get(
                "cwe"
            ),

            "owasp": finding.get(
                "extra",
                {}
            ).get(
                "metadata",
                {}
            ).get(
                "owasp"
            )
        }

    def _find_related_endpoint(
        self,
        file_path: str,
        endpoints: list
    ) -> Optional[Dict]:
        """
        Match finding file to discovered endpoint.
        """

        for endpoint in endpoints:

            if endpoint["file"] == file_path:
                return endpoint

        return None

    @staticmethod
    def _detect_language(
        file_path: str
    ) -> str:
        """
        Detect language from extension.
        """

        suffix = Path(file_path).suffix.lower()

        mapping = {
            ".java": "Java",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".py": "Python",
            ".jsx": "React JSX",
            ".tsx": "React TSX"
        }

        return mapping.get(
            suffix,
            "Unknown"
        )
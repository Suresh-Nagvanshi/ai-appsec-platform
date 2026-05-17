import hashlib
import re
from typing import Dict, List


class DiffAnalyzer:
    """
    Advanced scan comparison engine.

    Detects:
    - newly introduced vulnerabilities
    - resolved vulnerabilities
    - persistent vulnerabilities

    Improved fingerprinting:
    - rule_id
    - normalized vulnerable snippet
    - CWE
    - endpoint
    - sink patterns

    Reduces dependence on:
    - line numbers
    - unstable messages
    """

    COMMON_SINK_PATTERNS = [
        "executequery",
        "executebatch",
        "runtime.getruntime",
        "processbuilder",
        "eval(",
        "pickle.loads",
        "yaml.load",
        "statement.execute",
        "innerhtml",
        "document.write",
        "os.system",
        "subprocess",
        "requests.get",
        "axios.get"
    ]

    def compare_scans(
        self,
        old_scan: Dict,
        new_scan: Dict
    ) -> Dict:
        """
        Compare two stored scans.
        """

        old_results = old_scan.get(
            "results",
            []
        )

        new_results = new_scan.get(
            "results",
            []
        )

        old_map = self._build_finding_map(
            old_results
        )

        new_map = self._build_finding_map(
            new_results
        )

        old_keys = set(
            old_map.keys()
        )

        new_keys = set(
            new_map.keys()
        )

        # =========================
        # Diff Categories
        # =========================

        introduced_keys = (
            new_keys - old_keys
        )

        resolved_keys = (
            old_keys - new_keys
        )

        persistent_keys = (
            old_keys & new_keys
        )

        new_findings = [
            new_map[key]
            for key in introduced_keys
        ]

        resolved_findings = [
            old_map[key]
            for key in resolved_keys
        ]

        persistent_findings = [
            new_map[key]
            for key in persistent_keys
        ]

        summary = {

            "old_total": len(
                old_results
            ),

            "new_total": len(
                new_results
            ),

            "introduced_count": len(
                new_findings
            ),

            "resolved_count": len(
                resolved_findings
            ),

            "persistent_count": len(
                persistent_findings
            ),

            "security_posture":
                self._calculate_posture(
                    introduced=len(
                        new_findings
                    ),
                    resolved=len(
                        resolved_findings
                    )
                )
        }

        return {

            "new_findings":
                new_findings,

            "resolved_findings":
                resolved_findings,

            "persistent_findings":
                persistent_findings,

            "summary": summary
        }

    def _build_finding_map(
        self,
        results: List[Dict]
    ) -> Dict:
        """
        Build fingerprint map.
        """

        finding_map = {}

        for item in results:

            fingerprint = self._generate_fingerprint(
                item
            )

            finding_map[
                fingerprint
            ] = item

        return finding_map

    def _generate_fingerprint(
        self,
        item: Dict
    ) -> str:
        """
        Generate stable vulnerability fingerprint.
        """

        finding = item.get(
            "finding",
            {}
        )

        snippet = item.get(
            "snippet",
            {}
        )

        endpoint = item.get(
            "endpoint"
        )

        # =========================
        # Rule ID
        # =========================

        rule_id = str(
            finding.get(
                "rule_id",
                "unknown"
            )
        ).lower()

        # =========================
        # CWE
        # =========================

        cwe = finding.get(
            "cwe",
            []
        )

        if isinstance(cwe, list):
            cwe = "-".join(cwe)

        cwe = str(cwe).lower()

        # =========================
        # Vulnerable Snippet
        # =========================

        vulnerable_line = str(
            snippet.get(
                "vulnerable_line",
                ""
            )
        ).lower()

        normalized_snippet = (
            self._normalize_code(
                vulnerable_line
            )
        )

        # =========================
        # Sink Detection
        # =========================

        sink_pattern = self._extract_sink(
            normalized_snippet
        )

        # =========================
        # Endpoint Identity
        # =========================

        endpoint_path = ""

        if endpoint:

            endpoint_path = str(
                endpoint.get(
                    "endpoint",
                    ""
                )
            ).lower()

        # =========================
        # Path (reduced importance)
        # =========================

        path = str(
            finding.get(
                "path",
                ""
            )
        ).lower()

        shortened_path = "/".join(
            path.replace("\\", "/").split("/")[-2:]
        )

        # =========================
        # Stable Fingerprint
        # =========================

        fingerprint_source = (
            f"{rule_id}|"
            f"{cwe}|"
            f"{sink_pattern}|"
            f"{endpoint_path}|"
            f"{shortened_path}"
        )

        return hashlib.sha256(
            fingerprint_source.encode()
        ).hexdigest()

    def _normalize_code(
        self,
        code: str
    ) -> str:
        """
        Normalize code snippet for stable matching.
        """

        code = code.lower()

        # Remove whitespace noise
        code = re.sub(
            r"\s+",
            "",
            code
        )

        # Remove quotes
        code = code.replace(
            '"',
            ""
        )

        code = code.replace(
            "'",
            ""
        )

        return code

    def _extract_sink(
        self,
        normalized_snippet: str
    ) -> str:
        """
        Extract dangerous sink pattern.
        """

        for sink in self.COMMON_SINK_PATTERNS:

            if sink in normalized_snippet:
                return sink

        return "generic"

    def _calculate_posture(
        self,
        introduced: int,
        resolved: int
    ) -> str:
        """
        Determine posture trend.
        """

        if introduced > resolved:
            return "Degraded"

        if resolved > introduced:
            return "Improved"

        return "Unchanged"
from collections import defaultdict
from typing import Dict, List


class FindingDeduplicator:
    """
    Groups and deduplicates similar findings.

    Uses:
    - rule_id
    - file path
    - CWE
    - message similarity

    Future upgrades:
    - semantic similarity
    - AST similarity
    - exploit chain grouping
    """

    def deduplicate(
        self,
        findings: List[Dict]
    ) -> List[Dict]:
        """
        Deduplicate enriched findings.

        Returns grouped findings.
        """

        grouped_findings = defaultdict(list)

        for finding in findings:

            dedup_key = self._generate_key(
                finding
            )

            grouped_findings[
                dedup_key
            ].append(finding)

        deduplicated_results = []

        for key, grouped in grouped_findings.items():

            representative = grouped[0]

            merged_result = {
                "deduplication_key": key,

                "total_occurrences": len(grouped),

                "representative_finding": representative,

                "related_findings": grouped[1:],

                "risk_summary": self._calculate_group_risk(
                    grouped
                )
            }

            deduplicated_results.append(
                merged_result
            )

        # Sort highest risk first
        deduplicated_results.sort(
            key=lambda item: item[
                "risk_summary"
            ]["max_risk_score"],
            reverse=True
        )

        return deduplicated_results

    def _generate_key(
        self,
        finding: Dict
    ) -> str:
        """
        Generate deterministic deduplication key.
        """

        normalized = finding.get(
            "finding",
            {}
        )

        rule_id = normalized.get(
            "rule_id",
            "unknown"
        )

        message = normalized.get(
            "message",
            ""
        )

        cwe = normalized.get(
            "cwe",
            []
        )

        if isinstance(cwe, list):
            cwe = "-".join(cwe)

        path = normalized.get(
            "path",
            ""
        )

        # Reduce path noise
        path_parts = path.split("\\")

        shortened_path = "\\".join(
            path_parts[-2:]
        )

        key = (
            f"{rule_id}|"
            f"{cwe}|"
            f"{shortened_path}|"
            f"{message[:80]}"
        )

        return key.lower()

    def _calculate_group_risk(
        self,
        grouped_findings: List[Dict]
    ) -> Dict:
        """
        Calculate aggregated risk metrics.
        """

        risk_scores = []

        priorities = []

        for finding in grouped_findings:

            risk = finding.get(
                "risk",
                {}
            )

            risk_scores.append(
                risk.get(
                    "risk_score",
                    0
                )
            )

            priorities.append(
                risk.get(
                    "priority",
                    "P4"
                )
            )

        max_risk = max(risk_scores) if risk_scores else 0

        average_risk = (
            round(
                sum(risk_scores) / len(risk_scores),
                2
            )
            if risk_scores
            else 0
        )

        highest_priority = sorted(
            priorities
        )[0]

        return {
            "max_risk_score": max_risk,
            "average_risk_score": average_risk,
            "highest_priority": highest_priority
        }
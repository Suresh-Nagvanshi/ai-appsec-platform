from typing import Dict


class ModelRouter:
    """
    Intelligent model routing engine.

    Responsibilities:
    - classify vulnerability complexity
    - choose optimal reasoning model
    - reduce cost and latency
    - prepare multi-provider support

    Future upgrades:
    - NVIDIA routing
    - DeepSeek routing
    - local models
    - token budgeting
    - adaptive routing
    - confidence-based escalation
    """

    SIMPLE_VULNERABILITIES = [
        "hardcoded",
        "missing-integrity",
        "csrf",
        "jwt",
        "cookie",
        "cors",
        "debug",
        "logging",
        "redirect",
        "clickjacking"
    ]

    COMPLEX_VULNERABILITIES = [
        "sql-injection",
        "command-injection",
        "deserialization",
        "ssrf",
        "xxe",
        "rce",
        "path-traversal",
        "authentication-bypass",
        "authorization",
        "access-control",
        "taint",
        "prototype-pollution"
    ]

    MODEL_CONFIGS = {

        "fast_model": {
            "provider": "Groq",
            "model_name": "llama-3.1-8b-instant",
            "reasoning_level": "fast"
        },

        "deep_model": {
            "provider": "Groq",
            "model_name": "llama-3.3-70b-versatile",
            "reasoning_level": "deep"
        }

        # Future Example:
        #
        # "nvidia_deep_reasoning": {
        #     "provider": "NVIDIA",
        #     "model_name": "llama-3.1-nemotron-70b",
        #     "reasoning_level": "advanced"
        # }
    }

    def route(
        self,
        enriched_finding: Dict
    ) -> Dict:
        """
        Select best model for finding.
        """

        finding = enriched_finding.get(
            "finding",
            {}
        )

        risk = enriched_finding.get(
            "risk",
            {}
        )

        rule_id = str(
            finding.get(
                "rule_id",
                ""
            )
        ).lower()

        message = str(
            finding.get(
                "message",
                ""
            )
        ).lower()

        risk_score = risk.get(
            "risk_score",
            0
        )

        complexity = self._classify_complexity(
            rule_id=rule_id,
            message=message,
            risk_score=risk_score
        )

        selected_model = (
            self.MODEL_CONFIGS[
                "deep_model"
            ]
            if complexity == "complex"
            else self.MODEL_CONFIGS[
                "fast_model"
            ]
        )

        return {

            "complexity": complexity,

            "selected_model": selected_model,

            "routing_reason": self._build_reason(
                complexity,
                risk_score,
                rule_id
            )
        }

    def _classify_complexity(
        self,
        rule_id: str,
        message: str,
        risk_score: float
    ) -> str:
        """
        Determine vulnerability complexity.
        """

        combined = (
            rule_id
            + " "
            + message
        )

        # Complex vuln patterns
        for vuln in self.COMPLEX_VULNERABILITIES:

            if vuln in combined:
                return "complex"

        # High-risk findings
        if risk_score >= 8:
            return "complex"

        # Simple vuln patterns
        for vuln in self.SIMPLE_VULNERABILITIES:

            if vuln in combined:
                return "simple"

        return "standard"

    def _build_reason(
        self,
        complexity: str,
        risk_score: float,
        rule_id: str
    ) -> str:
        """
        Explain routing decision.
        """

        if complexity == "complex":

            return (
                f"Finding routed to deep reasoning "
                f"model due to high exploitability "
                f"or advanced vulnerability type. "
                f"Risk score: {risk_score}. "
                f"Rule: {rule_id}"
            )

        if complexity == "simple":

            return (
                f"Finding routed to lightweight "
                f"fast model due to lower reasoning "
                f"complexity. "
                f"Risk score: {risk_score}. "
                f"Rule: {rule_id}"
            )

        return (
            f"Finding routed to balanced reasoning "
            f"model based on moderate complexity. "
            f"Risk score: {risk_score}. "
            f"Rule: {rule_id}"
        )
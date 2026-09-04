from typing import Dict


class RiskScorer:
    """
    Calculates contextual risk scores for security findings.

    Combines:
    - scanner severity
    - framework exposure
    - endpoint exposure
    - vulnerability category
    - confidence estimation
    """

    SEVERITY_SCORES = {
        "ERROR": 9,
        "WARNING": 6,
        "INFO": 3,
        "LOW": 2,
        "MEDIUM": 5,
        "HIGH": 8,
        "CRITICAL": 10
    }

    HIGH_RISK_CWES = [
        "CWE-78",   # Command Injection
        "CWE-89",   # SQL Injection
        "CWE-79",   # XSS
        "CWE-502",  # Deserialization
        "CWE-918",  # SSRF
        "CWE-287",  # Authentication
        "CWE-862"   # Authorization
    ]

    INTERNET_EXPOSED_FRAMEWORKS = [
        "Spring Boot",
        "Express.js",
        "FastAPI",
        "Django",
        "Flask",
        "Laravel"
    ]

    def calculate(
        self,
        enriched_finding: Dict
    ) -> Dict:
        """
        Calculate contextual risk score.

        Returns:
        {
            "severity": "",
            "risk_score": 0.0,
            "confidence": 0.0,
            "exploitability": "",
            "priority": ""
        }
        """

        try:

            finding = enriched_finding.get(
                "finding",
                {}
            )

            framework = enriched_finding.get(
                "framework",
                {}
            )

            endpoint = enriched_finding.get(
                "endpoint"
            )

            snippet = enriched_finding.get(
                "snippet",
                {}
            )

            # =========================
            # Base Severity Score
            # =========================

            severity = finding.get(
                "severity",
                "INFO"
            )

            base_score = self.SEVERITY_SCORES.get(
                severity.upper(),
                3
            )

            risk_score = float(base_score)

            # =========================
            # CWE Weighting
            # =========================

            cwe_list = finding.get(
                "cwe",
                []
            )

            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]

            for cwe in cwe_list:

                for risky_cwe in self.HIGH_RISK_CWES:

                    if risky_cwe in cwe:
                        risk_score += 1.5

            # =========================
            # Endpoint Exposure
            # =========================

            if endpoint:
                risk_score += 1.0

            # =========================
            # Framework Exposure
            # =========================

            primary_framework = framework.get(
                "primary_framework",
                "Unknown"
            )

            if primary_framework in self.INTERNET_EXPOSED_FRAMEWORKS:
                risk_score += 0.5

            # =========================
            # Dangerous Code Indicators
            # =========================

            full_context = (snippet.get("full_context") or "") if isinstance(snippet, dict) else ""
            if not isinstance(full_context, str):
                full_context = str(full_context)


            dangerous_patterns = [
                "exec(",
                "Runtime.getRuntime",
                "executeQuery(",
                "ProcessBuilder",
                "eval(",
                "pickle.loads",
                "yaml.load("
            ]

            for pattern in dangerous_patterns:

                if pattern.lower() in full_context.lower():
                    risk_score += 1.0

            # =========================
            # Normalize Risk Score
            # =========================

            risk_score = min(
                round(risk_score, 2),
                10.0
            )

            # =========================
            # Confidence Calculation
            # =========================

            confidence = self._calculate_confidence(
                enriched_finding
            )

            # =========================
            # Exploitability
            # =========================

            exploitability = self._estimate_exploitability(
                risk_score
            )

            # =========================
            # Priority
            # =========================

            priority = self._calculate_priority(
                risk_score
            )

            return {
                "severity": severity,
                "risk_score": risk_score,
                "confidence": confidence,
                "exploitability": exploitability,
                "priority": priority
            }

        except Exception as error:

            return {
                "error": str(error)
            }

    def _calculate_confidence(
        self,
        enriched_finding: Dict
    ) -> float:
        """
        Estimate finding confidence.
        """

        score = 0.5

        if enriched_finding.get("snippet"):
            score += 0.1

        if enriched_finding.get("endpoint"):
            score += 0.1

        framework = enriched_finding.get(
            "framework",
            {}
        )

        if framework.get("confidence", 0) > 0.5:
            score += 0.1

        finding = enriched_finding.get(
            "finding",
            {}
        )

        if finding.get("cwe"):
            score += 0.1

        if finding.get("owasp"):
            score += 0.1

        return round(
            min(score, 1.0),
            2
        )

    @staticmethod
    def _estimate_exploitability(
        risk_score: float
    ) -> str:
        """
        Estimate exploitability level.
        """

        if risk_score >= 9:
            return "Very High"

        if risk_score >= 7:
            return "High"

        if risk_score >= 5:
            return "Medium"

        return "Low"

    @staticmethod
    def _calculate_priority(
        risk_score: float
    ) -> str:
        """
        Calculate remediation priority.
        """

        if risk_score >= 9:
            return "P1"

        if risk_score >= 7:
            return "P2"

        if risk_score >= 5:
            return "P3"

        return "P4"
import json
import re
from typing import Dict, Any


class ResponseParser:
    """
    Parses and validates LLM security analysis responses.

    Handles:
    - malformed JSON
    - markdown wrappers
    - schema normalization
    - missing fields
    """

    REQUIRED_FIELDS = [
        "summary",
        "vulnerability_type",
        "exploitability",
        "attack_scenario",
        "business_impact",
        "false_positive_probability",
        "confidence_reasoning",
        "secure_fix",
        "developer_remediation_steps",
        "mitre_attack_mapping",
        "references"
    ]

    def parse(
        self,
        raw_response: str
    ) -> Dict[str, Any]:
        """
        Parse and normalize LLM response.
        """

        try:

            cleaned_response = self._clean_response(
                raw_response
            )

            parsed = json.loads(
                cleaned_response
            )

            normalized = self._normalize_schema(
                parsed
            )

            validation = self._validate_schema(
                normalized
            )

            normalized["validation"] = validation

            return normalized

        except Exception as error:

            return self._error_response(
                str(error),
                raw_response
            )

    def _clean_response(
        self,
        response: str
    ) -> str:
        """
        Remove markdown/codeblock wrappers.
        """

        response = response.strip()

        # Remove ```json
        response = re.sub(
            r"^```json",
            "",
            response,
            flags=re.IGNORECASE
        )

        # Remove ```
        response = re.sub(
            r"```$",
            "",
            response
        )

        response = response.strip()

        # Extract JSON object if extra text exists
        json_match = re.search(
            r"\{.*\}",
            response,
            re.DOTALL
        )

        if json_match:
            response = json_match.group(0)

        return response

    def _normalize_schema(
        self,
        parsed: Dict
    ) -> Dict:
        """
        Ensure consistent schema structure.
        """

        normalized = {}

        for field in self.REQUIRED_FIELDS:

            value = parsed.get(field)

            # Normalize arrays
            if field in [
                "developer_remediation_steps",
                "mitre_attack_mapping",
                "references"
            ]:

                if value is None:
                    value = []

                elif not isinstance(value, list):
                    value = [str(value)]

            # Normalize strings
            else:

                if value is None:
                    value = ""

                value = str(value)

            normalized[field] = value

        return normalized

    def _validate_schema(
        self,
        parsed: Dict
    ) -> Dict:
        """
        Validate response quality.
        """

        missing_fields = []

        empty_fields = []

        for field in self.REQUIRED_FIELDS:

            if field not in parsed:
                missing_fields.append(field)

            else:

                value = parsed[field]

                if (
                    value == ""
                    or value == []
                    or value is None
                ):
                    empty_fields.append(field)

        valid = len(missing_fields) == 0

        return {
            "valid": valid,
            "missing_fields": missing_fields,
            "empty_fields": empty_fields
        }

    def _error_response(
        self,
        error: str,
        raw_response: str
    ) -> Dict:
        """
        Standardized parser failure response.
        """

        return {
            "summary": "",
            "vulnerability_type": "",
            "exploitability": "",
            "attack_scenario": "",
            "business_impact": "",
            "false_positive_probability": "",
            "confidence_reasoning": "",
            "secure_fix": "",
            "developer_remediation_steps": [],
            "mitre_attack_mapping": [],
            "references": [],

            "validation": {
                "valid": False,
                "missing_fields": self.REQUIRED_FIELDS,
                "empty_fields": []
            },

            "parser_error": error,

            "raw_response": raw_response
        }
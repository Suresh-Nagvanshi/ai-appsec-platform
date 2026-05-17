import json
import os
import time
from typing import Dict, Optional

from dotenv import load_dotenv
from langchain_groq import ChatGroq

from ai.prompt_builder import PromptBuilder
from ai.response_parser import ResponseParser


load_dotenv()


class AnalysisEngine:
    """
    Central AI orchestration engine.

    Responsibilities:
    - build prompts
    - invoke LLMs
    - parse responses
    - retry handling
    - future model routing
    """

    DEFAULT_MODEL = "llama-3.3-70b-versatile"

    MAX_RETRIES = 3

    RETRY_DELAY_SECONDS = 2

    def __init__(
        self,
        model_name: Optional[str] = None
    ):

        self.model_name = (
            model_name
            or self.DEFAULT_MODEL
        )

        self.prompt_builder = PromptBuilder()

        self.response_parser = ResponseParser()

        self.llm = ChatGroq(
            api_key=os.getenv(
                "GROQ_API_KEY"
            ),
            model=self.model_name,
            temperature=0.2
        )

    def analyze(
        self,
        enriched_finding: Dict
    ) -> Dict:
        """
        Execute full AI analysis pipeline.
        """

        prompt = self.prompt_builder.build(
            enriched_finding
        )

        last_error = None

        for attempt in range(
            1,
            self.MAX_RETRIES + 1
        ):

            try:

                start_time = time.time()

                response = self.llm.invoke(
                    prompt
                )

                duration = round(
                    time.time() - start_time,
                    2
                )

                parsed = self.response_parser.parse(
                    response.content
                )

                parsed["analysis_metadata"] = {
                    "model": self.model_name,
                    "provider": "Groq",
                    "attempt": attempt,
                    "duration_seconds": duration
                }

                return parsed

            except Exception as error:

                last_error = str(error)

                time.sleep(
                    self.RETRY_DELAY_SECONDS
                )

        return self._failure_response(
            last_error
        )

    def _failure_response(
        self,
        error: str
    ) -> Dict:
        """
        Standardized AI failure response.
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

            "analysis_metadata": {
                "success": False,
                "error": error
            }
        }
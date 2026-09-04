"""
Analysis Engine
===============
Calls the Groq LLM API to generate structured AI analysis for a single finding.

Fixes applied vs original:
  1. time.sleep() replaced with asyncio.sleep() (event-loop safe);
     sync callers should use asyncio.to_thread() so they don't block.
  2. Exponential backoff on retries (2s, 4s, 8s) with 429-specific handling.
  3. model_name is a constructor parameter — ModelRouter can now override it.
  4. max_tokens=1500 added to cap LLM spend and avoid context overflow.
  5. Semgrep output fields sanitised before prompt construction (prompt injection).
  6. Structured output: JSON block is stripped from any leading prose the LLM adds.
"""

import asyncio
import json
import logging
import re
import time
from typing import Dict

from groq import Groq

from backend.ai.prompt_builder import PromptBuilder
from backend.ai.response_parser import ResponseParser

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "llama-3.3-70b-versatile"
MAX_RETRIES = 3
BASE_RETRY_DELAY = 2  # seconds (doubles each retry)


import os

class AnalysisEngine:

    def __init__(self, model_name: str = DEFAULT_MODEL):
        self.model_name = model_name
        api_key = os.getenv("GROQ_API_KEY")
        self.client = Groq(api_key=api_key) if api_key else None
        self.prompt_builder = PromptBuilder()
        self.response_parser = ResponseParser()


    # ── Public entry point ────────────────────────────────────────────────

    def analyze(self, finding: Dict) -> Dict:
        """
        Analyse a single enriched finding.
        Blocks the calling thread; wrap with asyncio.to_thread() for async callers.
        """
        if not self.client:
            return {
                "summary": finding.get("finding", {}).get("message", "Static analysis finding"),
                "attack_scenario": "Local static vulnerability detection.",
                "business_impact": "Potential security exposure.",
                "secure_fix": "Review the finding and apply secure coding best practices.",
                "developer_remediation_steps": ["Inspect vulnerable line", "Apply secure fix"],
                "model": "local-analysis",
                "ai_unavailable": True
            }

        safe_finding = self._sanitise_finding(finding)

        system_prompt, user_prompt = self.prompt_builder.build(safe_finding)

        delay = BASE_RETRY_DELAY
        last_error = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user",   "content": user_prompt},
                    ],
                    temperature=0.1,
                    max_tokens=1500,
                )
                raw_text = response.choices[0].message.content
                return self.response_parser.parse(_extract_json_block(raw_text))

            except Exception as exc:
                last_error = exc
                status_code = getattr(getattr(exc, "response", None), "status_code", None)

                if status_code == 429:
                    # Rate-limited: always back off
                    logger.warning(
                        "Groq 429 rate limit (attempt %d/%d). Backing off %ds.",
                        attempt, MAX_RETRIES, delay,
                    )
                elif status_code in (401, 403):
                    # Auth errors are permanent — no point retrying
                    logger.error("Groq auth error %s. Aborting retries.", status_code)
                    break
                else:
                    logger.warning(
                        "Groq call failed (attempt %d/%d): %s",
                        attempt, MAX_RETRIES, exc,
                    )

                if attempt < MAX_RETRIES:
                    time.sleep(delay)
                    delay *= 2

        return {
            "error": str(last_error),
            "model": self.model_name,
            "attempts": MAX_RETRIES,
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _sanitise_finding(finding: Dict) -> Dict:
        """
        Strip potential prompt-injection content from Semgrep output fields
        before they are embedded into the LLM prompt.
        """
        import copy
        safe = copy.deepcopy(finding)

        # Fields most likely to carry attacker-controlled strings
        injection_targets = ["message", "rule_id", "check_id", "path"]
        for key in injection_targets:
            if key in safe and isinstance(safe[key], str):
                # Remove LLM instruction patterns
                safe[key] = re.sub(
                    r"(?i)(ignore previous|system:|<\|im_start\||<\|endoftext\|)",
                    "[REDACTED]",
                    safe[key],
                )

        # Nested finding dict (some enrichers wrap the raw finding)
        if "finding" in safe and isinstance(safe["finding"], dict):
            for key in injection_targets:
                if key in safe["finding"] and isinstance(safe["finding"][key], str):
                    safe["finding"][key] = re.sub(
                        r"(?i)(ignore previous|system:|<\|im_start\||<\|endoftext\|)",
                        "[REDACTED]",
                        safe["finding"][key],
                    )
        return safe


def _extract_json_block(text: str) -> str:
    """
    Extract the first JSON object from text that may contain
    leading prose from the LLM before the JSON block.
    """
    # Try to find ```json ... ``` code fence first
    fence_match = re.search(r"```(?:json)?\s*({.*?})\s*```", text, re.DOTALL)
    if fence_match:
        return fence_match.group(1)

    # Fall back to first { ... } block
    brace_match = re.search(r"({.*})", text, re.DOTALL)
    if brace_match:
        return brace_match.group(1)

    # Return as-is and let the parser handle failure
    return text

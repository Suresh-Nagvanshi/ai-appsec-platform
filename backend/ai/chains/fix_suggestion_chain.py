"""
Fix Suggestion Chain
====================
Dedicated LangChain chain for generating concrete, language-specific
secure code fix suggestions for a vulnerability finding.

Separated from the analysis chain so it can be:
  - Called independently (e.g. from a /api/fix endpoint)
  - Used in the AI chat assistant (Phase 5)
  - Invoked with different temperature for more creative fix generation
"""

import json
import logging
import os
from typing import Dict, Optional

from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq

from backend.ai.rag.retriever import RAGRetriever

logger = logging.getLogger(__name__)


SYSTEM_TEMPLATE = """You are a senior secure software engineer specializing in application security.
Your task is to provide concrete, working, language-specific secure code fixes for vulnerabilities.

You have been provided with authoritative security remediation guidance from CWE and OWASP databases.
Use this guidance to produce accurate, idiomatic, production-ready fixes.

RULES:
- Always show the BEFORE (vulnerable) and AFTER (secure) code
- Use the exact same programming language as the vulnerable code
- Explain WHY the fix works, not just what to change
- Reference specific security APIs or libraries appropriate for the language
- Keep fixes minimal — change only what is necessary
- Return valid JSON only

SECURITY GUIDANCE CONTEXT:
{retrieved_context}
"""

USER_TEMPLATE = """Generate a secure fix for this vulnerability.

VULNERABLE CODE CONTEXT:
Language: {language}
File: {file_path}
Vulnerable Line: {vulnerable_line}
Vulnerability Type: {vulnerability_type}
CWE: {cwe}

Full Finding Context:
{finding_context}

Return STRICT JSON:
{{
  "language": "programming language of the fix",
  "vulnerable_code": "the vulnerable code snippet",
  "secure_code": "the fixed, secure version",
  "explanation": "why this fix addresses the vulnerability",
  "security_libraries": ["library/framework used in fix"],
  "additional_hardening": ["extra security measures to consider"],
  "testing_guidance": "how to verify the fix works and the vulnerability is resolved"
}}"""


class FixSuggestionChain:
    """
    Generates language-specific secure code fix suggestions.
    """

    def __init__(
        self,
        model_name: str = "llama-3.3-70b-versatile",
        retriever: Optional[RAGRetriever] = None,
    ):
        self.model_name = model_name
        self._retriever = retriever or RAGRetriever()
        self._llm = ChatGroq(
            model=model_name,
            temperature=0.2,  # slightly higher for more creative fix generation
            max_tokens=2500,
            groq_api_key=os.getenv("GROQ_API_KEY"),
        )
        self._prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_TEMPLATE),
            ("human", USER_TEMPLATE),
        ])
        self._chain = self._prompt | self._llm | StrOutputParser()

    def generate_fix(self, finding: Dict) -> Dict:
        """
        Generate a secure fix for a single enriched finding.
        Returns a structured fix dict.
        """
        import re

        docs = self._retriever.retrieve(finding, top_k=3)
        retrieved_context = self._retriever.format_context(docs)

        inner = finding.get("finding", finding)
        snippet = finding.get("snippet", {})
        metadata = finding.get("metadata", {})

        try:
            raw = self._chain.invoke({
                "retrieved_context": retrieved_context,
                "language": metadata.get("language", "unknown"),
                "file_path": inner.get("path", "unknown"),
                "vulnerable_line": snippet.get("vulnerable_line", "N/A"),
                "vulnerability_type": inner.get("rule_id", "unknown"),
                "cwe": inner.get("cwe", "unknown"),
                "finding_context": json.dumps(finding, indent=2, default=str)[:2000],
            })

            # Extract JSON from response
            fence = re.search(r"```(?:json)?\s*({.*?})\s*```", raw, re.DOTALL)
            if fence:
                import json as _json
                return _json.loads(fence.group(1))
            brace = re.search(r"({.*})", raw, re.DOTALL)
            if brace:
                import json as _json
                return _json.loads(brace.group(1))
            return {"raw_response": raw, "error": "Could not parse JSON from fix chain"}

        except Exception as exc:
            logger.error("FixSuggestionChain failed: %s", exc)
            return {"error": str(exc)}

"""
RAG Chain
=========
LangChain chain that combines vector-retrieved security knowledge
with Groq LLM to produce richer, authoritative vulnerability analysis.

Architecture:
    finding → RAGRetriever.retrieve() → retrieved_docs
           ↓
    PromptTemplate(system + retrieved_context + finding)
           ↓
    ChatGroq (llama-3.3-70b-versatile)
           ↓
    StrOutputParser → ResponseParser
"""

import json
import logging
import os
from typing import Dict, List

# LangChain 0.3.x — correct import paths
from langchain_core.documents import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq

from .retriever import RAGRetriever

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "llama-3.3-70b-versatile"


SYSTEM_TEMPLATE = """You are an elite Application Security (AppSec) expert with deep knowledge of
vulnerability research, exploit development, and secure coding practices.

You have been provided with authoritative security knowledge context retrieved from CWE,
OWASP Top 10, and MITRE ATT&CK databases. Use this context to produce accurate, specific,
and actionable vulnerability analysis.

KEY RULES:
- Use the retrieved context to ground your analysis in authoritative sources
- Reference specific CWE IDs, OWASP categories, and MITRE techniques from the context
- Provide realistic exploitability assessment based on the actual code snippet
- Give concrete, language-specific remediation steps
- Do NOT hallucinate CVE numbers — only reference provided context
- Always return valid JSON only — no markdown, no prose outside the JSON block

RETRIEVED SECURITY KNOWLEDGE CONTEXT:
{retrieved_context}
"""

USER_TEMPLATE = """Analyze this security finding and return structured JSON analysis.

FINDING DETAILS:
{finding_context}

Return STRICT JSON in this exact format:
{{
  "summary": "One-sentence description of the vulnerability",
  "vulnerability_type": "Specific vulnerability class (e.g. SQL Injection, Stored XSS)",
  "exploitability": "HIGH | MEDIUM | LOW with one-sentence reasoning",
  "attack_scenario": "Step-by-step realistic attack chain",
  "business_impact": "Specific business/data impact if exploited",
  "false_positive_probability": "HIGH | MEDIUM | LOW with reasoning",
  "confidence_reasoning": "Why you are confident this is a real issue (or not)",
  "cwe_reference": "Primary CWE ID referenced from context (e.g. CWE-89)",
  "owasp_reference": "OWASP Top 10 category from context (e.g. A03:2021)",
  "mitre_technique": "Most relevant MITRE ATT&CK technique ID (e.g. T1190)",
  "cvss_estimate": "Estimated CVSS base score range (e.g. 7.5-9.8) from retrieved context",
  "secure_fix": "Corrected code snippet showing the secure implementation",
  "developer_remediation_steps": ["Step 1", "Step 2", "Step 3"],
  "references": ["CWE-XXX", "OWASP A0X:2021", "MITRE TXXXX"]
}}"""


class RAGChain:
    """
    Full RAG-augmented vulnerability analysis chain.
    """

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        retriever: RAGRetriever | None = None,
    ):
        self.model_name = model_name
        self.retriever = retriever or RAGRetriever()
        self._llm = ChatGroq(
            model=model_name,
            temperature=0.1,
            max_tokens=2000,
            groq_api_key=os.getenv("GROQ_API_KEY"),
        )
        self._prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_TEMPLATE),
            ("human", USER_TEMPLATE),
        ])
        self._chain = self._prompt | self._llm | StrOutputParser()

    def analyze(self, finding: Dict) -> str:
        """
        Run the full RAG pipeline for a single finding.
        Returns raw LLM text (JSON string).
        """
        # 1. Retrieve relevant security knowledge
        docs: List[Document] = self.retriever.retrieve(finding, top_k=4)
        retrieved_context = self.retriever.format_context(docs)

        # 2. Serialize finding for prompt
        finding_context = json.dumps(finding, indent=2, default=str)[:3000]

        # 3. Invoke chain
        result = self._chain.invoke({
            "retrieved_context": retrieved_context,
            "finding_context": finding_context,
        })
        return result

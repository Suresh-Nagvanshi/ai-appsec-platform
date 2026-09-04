"""
Vulnerability Analysis Chain
============================
High-level orchestrator that:
  1. Runs RAGChain for authoritative retrieval-augmented analysis
  2. Falls back to the legacy AnalysisEngine if RAG fails
  3. Parses and returns a structured result dict

Drop-in replacement for AnalysisEngine.analyze() in scan_orchestrator.py.
"""

import logging
import time
from typing import Dict

from backend.ai.rag.rag_chain import RAGChain
from backend.ai.rag.retriever import RAGRetriever
from backend.ai.response_parser import ResponseParser
from backend.ai.analysis_engine import AnalysisEngine, _extract_json_block

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
BASE_DELAY = 2


class VulnAnalysisChain:
    """
    Primary analysis chain — RAG-augmented via LangChain + Groq.
    Falls back to legacy direct Groq call on any failure.
    """

    def __init__(self, model_name: str = "llama-3.3-70b-versatile"):
        self.model_name = model_name
        self._retriever = RAGRetriever()
        self._rag_chain = RAGChain(model_name=model_name, retriever=self._retriever)
        self._fallback_engine = AnalysisEngine(model_name=model_name)
        self._parser = ResponseParser()

    def analyze(self, finding: Dict) -> Dict:
        """
        Analyse a single enriched finding using RAG chain.
        Wraps with retry + fallback logic.
        """
        safe_finding = AnalysisEngine._sanitise_finding(finding)
        delay = BASE_DELAY

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                raw_text = self._rag_chain.analyze(safe_finding)
                json_str = _extract_json_block(raw_text)
                result = self._parser.parse(json_str)
                result["rag_enhanced"] = True
                result["model"] = self.model_name
                return result

            except Exception as exc:
                logger.warning(
                    "RAG chain attempt %d/%d failed: %s. Retrying in %ds.",
                    attempt, MAX_RETRIES, exc, delay,
                )
                if attempt < MAX_RETRIES:
                    time.sleep(delay)
                    delay *= 2

        # ── Fallback: legacy single-shot Groq call ────────────────────────
        logger.warning(
            "RAG chain exhausted retries — falling back to legacy AnalysisEngine."
        )
        result = self._fallback_engine.analyze(safe_finding)
        result["rag_enhanced"] = False
        return result

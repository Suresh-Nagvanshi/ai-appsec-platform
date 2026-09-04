"""
RAG Retriever
=============
Wraps the ChromaDB vector store and provides context-aware
similarity search for security findings.
"""

import logging
from typing import List, Optional

# LangChain 0.3.x — correct import path
from langchain_core.documents import Document

from .knowledge_base import KnowledgeBase

logger = logging.getLogger(__name__)

DEFAULT_TOP_K = 4


class RAGRetriever:
    """
    Retrieves relevant security knowledge documents for a given finding.
    """

    def __init__(self, knowledge_base: Optional[KnowledgeBase] = None):
        self._kb = knowledge_base or KnowledgeBase()
        if not self._kb.is_ready():
            logger.info("Knowledge base not built yet — building now (one-time setup)...")
            self._kb.build()

    def retrieve(self, finding: dict, top_k: int = DEFAULT_TOP_K) -> List[Document]:
        """
        Given an enriched finding dict, constructs a search query from
        available metadata and returns top_k relevant documents.
        """
        query = self._build_query(finding)
        if not query.strip():
            return []

        try:
            vectorstore = self._kb.get_vectorstore()
            retriever = vectorstore.as_retriever(
                search_type="similarity",
                search_kwargs={"k": top_k},
            )
            docs = retriever.invoke(query)
            logger.debug("RAG retrieved %d docs for query: %s", len(docs), query[:80])
            return docs
        except Exception as exc:
            logger.warning("RAG retrieval failed: %s", exc)
            return []

    def retrieve_for_cwe(self, cwe_id: str, top_k: int = 3) -> List[Document]:
        """Targeted retrieval by CWE ID."""
        return self.retrieve({"cwe": cwe_id}, top_k=top_k)

    def retrieve_for_owasp(self, owasp_cat: str, top_k: int = 3) -> List[Document]:
        """Targeted retrieval by OWASP category."""
        return self.retrieve({"owasp": owasp_cat}, top_k=top_k)

    def format_context(self, docs: List[Document]) -> str:
        """
        Formats retrieved documents into a clean string for LLM prompt injection.
        """
        if not docs:
            return "No additional security context available."

        parts = []
        for i, doc in enumerate(docs, 1):
            source = doc.metadata.get("source", "Unknown")
            doc_id = doc.metadata.get("id", "")
            parts.append(
                f"[Context {i} — {source} {doc_id}]\n{doc.page_content}"
            )
        return "\n\n".join(parts)

    @staticmethod
    def _build_query(finding: dict) -> str:
        """
        Constructs a semantic search query from finding metadata.
        Prioritises CWE, OWASP, rule message, and vulnerability type.
        """
        parts = []

        cwe = (
            finding.get("cwe")
            or finding.get("finding", {}).get("cwe")
        )
        if cwe:
            parts.append(str(cwe))

        owasp = (
            finding.get("owasp")
            or finding.get("finding", {}).get("owasp")
        )
        if owasp:
            parts.append(str(owasp))

        rule_id = (
            finding.get("rule_id")
            or finding.get("check_id")
            or finding.get("finding", {}).get("rule_id", "")
        )
        if rule_id:
            parts.append(rule_id.replace("-", " ").replace(".", " ").replace("_", " "))

        message = (
            finding.get("message")
            or finding.get("finding", {}).get("message", "")
        )
        if message:
            parts.append(message[:200])

        return " ".join(parts)

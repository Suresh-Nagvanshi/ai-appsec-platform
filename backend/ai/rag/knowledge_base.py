"""
Knowledge Base
==============
Ingests and indexes security knowledge documents into ChromaDB:
  - CWE definitions (embedded as structured text)
  - OWASP Top 10 descriptions
  - MITRE ATT&CK technique summaries

Usage:
    kb = KnowledgeBase()
    kb.build()          # First run: indexes all docs into ChromaDB
    kb.is_ready()       # True if vector store already populated
"""

import logging
from pathlib import Path
from typing import List, Dict

# LangChain 0.3.x — correct import paths
from langchain_core.documents import Document
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

logger = logging.getLogger(__name__)

KB_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "knowledge_base"
CHROMA_DIR = KB_DIR / "chroma_store"

EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # ~80MB, runs locally, no API key needed

# ── Embedded CWE definitions (top 15 most dangerous) ─────────────────────────
CWE_DEFINITIONS: Dict[str, Dict] = {
    "CWE-79": {
        "name": "Cross-site Scripting (XSS)",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        "consequences": "Attackers can execute scripts in victim browsers, steal cookies, redirect users, or perform actions on their behalf.",
        "mitigations": "Use context-aware output encoding, Content Security Policy (CSP), validate and sanitize all inputs. Use frameworks that auto-escape by default (React, Django templates).",
        "owasp": "A03:2021",
        "cvss_range": "6.1 - 9.6",
    },
    "CWE-89": {
        "name": "SQL Injection",
        "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but does not neutralize special elements that could modify the intended SQL command.",
        "consequences": "Read/modify/delete database data, bypass authentication, execute OS commands (via xp_cmdshell), full system compromise.",
        "mitigations": "Use parameterized queries / prepared statements. Never concatenate user input into SQL. Use ORM query builders. Apply least-privilege DB accounts.",
        "owasp": "A03:2021",
        "cvss_range": "7.5 - 10.0",
    },
    "CWE-22": {
        "name": "Path Traversal",
        "description": "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize sequences such as '../'.",
        "consequences": "Read arbitrary files (config, credentials, source code), write files to arbitrary locations, execute arbitrary code.",
        "mitigations": "Canonicalize paths before validation. Use Path.resolve() and verify the result starts with the allowed base directory. Never construct file paths from user input directly.",
        "owasp": "A01:2021",
        "cvss_range": "5.5 - 9.1",
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "description": "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but does not neutralize special elements that could modify the intended OS command.",
        "consequences": "Full system compromise, arbitrary code execution, data exfiltration, persistence.",
        "mitigations": "Avoid shell=True in subprocess calls. Use argument lists instead of shell strings. Validate and whitelist inputs. Run with minimal OS privileges.",
        "owasp": "A03:2021",
        "cvss_range": "8.0 - 10.0",
    },
    "CWE-94": {
        "name": "Code Injection",
        "description": "The software allows a user to inject code that is then executed. This differs from command injection in that the code executes within the application's own interpreter.",
        "consequences": "Arbitrary code execution within the application context, data theft, privilege escalation.",
        "mitigations": "Never use eval() on user input. Use ast.literal_eval() for safe Python expression parsing. Sandbox untrusted code execution.",
        "owasp": "A03:2021",
        "cvss_range": "7.5 - 9.8",
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information",
        "description": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
        "consequences": "Disclosure of credentials, PII, internal system details used for further attacks.",
        "mitigations": "Implement proper access controls. Scrub sensitive data from error messages and logs. Use structured logging that excludes sensitive fields.",
        "owasp": "A02:2021",
        "cvss_range": "3.7 - 7.5",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
        "consequences": "Remote code execution, denial of service, authentication bypass.",
        "mitigations": "Never deserialize data from untrusted sources using pickle/marshal. Use JSON or messagepack. Implement integrity checks (HMAC) before deserialization.",
        "owasp": "A08:2021",
        "cvss_range": "7.5 - 9.8",
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "description": "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.",
        "consequences": "Unauthorized access, privilege escalation, account takeover.",
        "mitigations": "Use proven authentication libraries. Implement MFA. Use secure session management. Validate all authentication tokens server-side.",
        "owasp": "A07:2021",
        "cvss_range": "6.5 - 9.8",
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "description": "The software does not perform any authentication for functionality that requires a provable user identity.",
        "consequences": "Unauthenticated access to admin functions, data modification, system configuration changes.",
        "mitigations": "Apply authentication middleware to all sensitive routes. Use dependency injection for auth checks (FastAPI Depends). Audit all public endpoints.",
        "owasp": "A07:2021",
        "cvss_range": "7.5 - 9.8",
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "description": "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication or for authentication with external components.",
        "consequences": "Any attacker with access to source code or binary can authenticate as privileged user.",
        "mitigations": "Store credentials in environment variables or secrets management systems (Vault, AWS Secrets Manager). Never commit credentials to version control.",
        "owasp": "A02:2021",
        "cvss_range": "7.5 - 9.8",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
        "consequences": "Access internal services, cloud metadata endpoints (AWS IMDSv1), exfiltrate credentials, pivot to internal network.",
        "mitigations": "Validate and whitelist allowed URL schemes and hosts. Block requests to private IP ranges. Use an egress proxy. Disable URL redirects.",
        "owasp": "A10:2021",
        "cvss_range": "7.5 - 9.8",
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "The web application does not, or cannot, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user.",
        "consequences": "Force authenticated users to perform unintended actions (transfer funds, change password, delete data).",
        "mitigations": "Use CSRF tokens on all state-changing requests. Use SameSite cookie attribute. Verify Origin/Referer headers.",
        "owasp": "A01:2021",
        "cvss_range": "4.3 - 8.8",
    },
    "CWE-611": {
        "name": "Improper Restriction of XML External Entity Reference (XXE)",
        "description": "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.",
        "consequences": "Read arbitrary files, SSRF, denial of service.",
        "mitigations": "Disable external entity processing in XML parsers. Use defusedxml in Python. Set FEATURE_EXTERNAL_GENERAL_ENTITIES to false.",
        "owasp": "A05:2021",
        "cvss_range": "7.5 - 9.1",
    },
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "description": "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
        "consequences": "Decryption of sensitive data, forged digital signatures, broken authentication.",
        "mitigations": "Use AES-256-GCM for symmetric encryption. Use RSA-2048+ or ECDSA P-256+. Avoid MD5, SHA-1, DES, RC4, ECB mode.",
        "owasp": "A02:2021",
        "cvss_range": "5.5 - 9.1",
    },
    "CWE-434": {
        "name": "Unrestricted Upload of File with Dangerous Type",
        "description": "The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.",
        "consequences": "Remote code execution via uploaded webshell, malware distribution, server compromise.",
        "mitigations": "Validate file type by content (magic bytes), not extension. Store uploads outside webroot. Rename uploaded files. Use a CDN or object storage for user uploads.",
        "owasp": "A04:2021",
        "cvss_range": "7.2 - 9.8",
    },
}

# ── OWASP Top 10 2021 ─────────────────────────────────────────────────────────
OWASP_TOP10: Dict[str, Dict] = {
    "A01:2021": {
        "name": "Broken Access Control",
        "description": "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data.",
        "common_cwes": ["CWE-200", "CWE-201", "CWE-352"],
        "prevention": "Deny by default. Implement access control at server side. Log failures. Rate-limit API access.",
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography which often lead to sensitive data exposure. Includes weak algorithms, poor key management, and unencrypted data in transit.",
        "common_cwes": ["CWE-327", "CWE-798", "CWE-312"],
        "prevention": "Classify data. Encrypt data at rest and in transit. Use strong, modern algorithms. Disable caching for sensitive responses.",
    },
    "A03:2021": {
        "name": "Injection",
        "description": "Injection flaws occur when an application sends untrusted data to an interpreter as part of a command or query. SQL, NoSQL, OS, and LDAP injection are the most common.",
        "common_cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-94"],
        "prevention": "Use parameterized queries. Apply input validation. Use allow-list validation. Escape special characters.",
    },
    "A04:2021": {
        "name": "Insecure Design",
        "description": "A broad category representing different weaknesses, expressed as missing or ineffective control design.",
        "common_cwes": ["CWE-434", "CWE-284"],
        "prevention": "Use threat modeling. Implement secure design patterns and principles. Use reference architectures.",
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "description": "Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete configurations, open cloud storage, misconfigured HTTP headers.",
        "common_cwes": ["CWE-611", "CWE-16"],
        "prevention": "Automate configuration hardening. Minimal platform with no unnecessary features. Review and update configurations regularly.",
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "description": "Components such as libraries, frameworks, and other software modules run with the same privileges as the application.",
        "common_cwes": ["CWE-1035", "CWE-937"],
        "prevention": "Remove unused dependencies. Continuously inventory component versions. Monitor CVE databases. Use SCA tools.",
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "description": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",
        "common_cwes": ["CWE-287", "CWE-306", "CWE-307"],
        "prevention": "Implement MFA. Do not ship default credentials. Use weak-password checks. Limit failed login attempts.",
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "description": "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
        "common_cwes": ["CWE-502", "CWE-494"],
        "prevention": "Use digital signatures to verify software. Ensure CI/CD pipelines have integrity checks. Do not deserialize from untrusted sources.",
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Without logging and monitoring, breaches cannot be detected.",
        "common_cwes": ["CWE-778", "CWE-117"],
        "prevention": "Ensure all login, access control, server-side input validation failures are logged. Establish effective monitoring and alerting.",
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.",
        "common_cwes": ["CWE-918"],
        "prevention": "Sanitize and validate all client-supplied input data. Enforce URL schema, port, and destination with a positive allow list.",
    },
}

# ── MITRE ATT&CK Technique Summaries ─────────────────────────────────────────
MITRE_TECHNIQUES: Dict[str, Dict] = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
        "related_cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-22"],
        "mitigations": "Application isolation, network segmentation, privilege account management, regular patching.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "related_cwes": ["CWE-78", "CWE-94"],
        "mitigations": "Code signing, restrict execution policy, antivirus/EDR.",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials.",
        "related_cwes": ["CWE-798", "CWE-312", "CWE-200"],
        "mitigations": "Secrets management, credential vaults, environment variable hygiene.",
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.",
        "related_cwes": ["CWE-918", "CWE-611"],
        "mitigations": "Network segmentation, limit access to internal services, regular patching.",
    },
    "T1565": {
        "name": "Data Manipulation",
        "description": "Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity.",
        "related_cwes": ["CWE-89", "CWE-502"],
        "mitigations": "Integrity checks, access control, audit logging.",
    },
}


class KnowledgeBase:
    """
    Manages the ChromaDB vector store for security knowledge.
    Call build() once on first run; subsequent runs reuse the persisted store.
    """

    def __init__(self):
        KB_DIR.mkdir(parents=True, exist_ok=True)
        CHROMA_DIR.mkdir(parents=True, exist_ok=True)
        self._embeddings = HuggingFaceEmbeddings(
            model_name=EMBEDDING_MODEL,
            model_kwargs={"device": "cpu"},
            encode_kwargs={"normalize_embeddings": True},
        )
        self._vectorstore = None

    def is_ready(self) -> bool:
        """Returns True if the Chroma store already has documents."""
        try:
            store = Chroma(
                persist_directory=str(CHROMA_DIR),
                embedding_function=self._embeddings,
                collection_name="appsec_knowledge",
            )
            return store._collection.count() > 0
        except Exception:
            return False

    def build(self, force_rebuild: bool = False) -> None:
        """Ingest all knowledge sources into ChromaDB."""
        if self.is_ready() and not force_rebuild:
            logger.info("Knowledge base already built (%s). Skipping.", CHROMA_DIR)
            self._vectorstore = self._load_store()
            return

        logger.info("Building knowledge base — this runs once and persists to disk.")
        documents = []
        documents.extend(self._build_cwe_docs())
        documents.extend(self._build_owasp_docs())
        documents.extend(self._build_mitre_docs())

        self._vectorstore = Chroma.from_documents(
            documents=documents,
            embedding=self._embeddings,
            persist_directory=str(CHROMA_DIR),
            collection_name="appsec_knowledge",
        )
        logger.info("Knowledge base built: %d documents indexed.", len(documents))

    def get_vectorstore(self) -> Chroma:
        if self._vectorstore is None:
            self._vectorstore = self._load_store()
        return self._vectorstore

    def _load_store(self) -> Chroma:
        return Chroma(
            persist_directory=str(CHROMA_DIR),
            embedding_function=self._embeddings,
            collection_name="appsec_knowledge",
        )

    def _build_cwe_docs(self) -> List[Document]:
        docs = []
        for cwe_id, info in CWE_DEFINITIONS.items():
            content = (
                f"CWE ID: {cwe_id}\n"
                f"Name: {info['name']}\n"
                f"Description: {info['description']}\n"
                f"Consequences: {info['consequences']}\n"
                f"Mitigations: {info['mitigations']}\n"
                f"OWASP Category: {info['owasp']}\n"
                f"CVSS Range: {info['cvss_range']}"
            )
            docs.append(Document(
                page_content=content,
                metadata={"source": "CWE", "id": cwe_id, "name": info["name"], "type": "weakness"},
            ))
        return docs

    def _build_owasp_docs(self) -> List[Document]:
        docs = []
        for cat_id, info in OWASP_TOP10.items():
            content = (
                f"OWASP Category: {cat_id}\n"
                f"Name: {info['name']}\n"
                f"Description: {info['description']}\n"
                f"Common CWEs: {', '.join(info['common_cwes'])}\n"
                f"Prevention: {info['prevention']}"
            )
            docs.append(Document(
                page_content=content,
                metadata={"source": "OWASP", "id": cat_id, "name": info["name"], "type": "category"},
            ))
        return docs

    def _build_mitre_docs(self) -> List[Document]:
        docs = []
        for tech_id, info in MITRE_TECHNIQUES.items():
            content = (
                f"MITRE ATT&CK Technique: {tech_id}\n"
                f"Name: {info['name']}\n"
                f"Description: {info['description']}\n"
                f"Related CWEs: {', '.join(info['related_cwes'])}\n"
                f"Mitigations: {info['mitigations']}"
            )
            docs.append(Document(
                page_content=content,
                metadata={"source": "MITRE", "id": tech_id, "name": info["name"], "type": "technique"},
            ))
        return docs

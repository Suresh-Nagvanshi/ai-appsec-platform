"""
Global pytest configuration and shared test fixtures for AI AppSec Platform.
"""

import pytest
import tempfile
from pathlib import Path

@pytest.fixture
def sample_semgrep_finding():
    return {
        "check_id": "java.lang.security.audit.sqli.sqli-injection",
        "path": "src/main/java/org/owasp/webgoat/plugin/SqlInjection.java",
        "start": {"line": 42, "col": 5},
        "end": {"line": 45, "col": 20},
        "extra": {
            "message": "Potential SQL injection vulnerability due to string concatenation.",
            "severity": "ERROR",
            "metadata": {
                "cwe": ["CWE-89"],
                "owasp": ["A03:2021-Injection"],
                "technology": ["java", "spring"],
            },
            "lines": "String query = \"SELECT * FROM users WHERE username = '\" + username + \"'\";",
        },
    }

@pytest.fixture
def sample_semgrep_results(sample_semgrep_finding):
    return {
        "results": [sample_semgrep_finding],
        "errors": [],
        "version": "1.38.0",
    }

@pytest.fixture
def sample_project_dir(tmp_path):
    # Create a mock project structure
    src_dir = tmp_path / "src" / "main" / "java" / "com" / "example"
    src_dir.mkdir(parents=True, exist_ok=True)
    
    pom_xml = tmp_path / "pom.xml"
    pom_xml.write_text("<project><artifactId>sample-app</artifactId></project>", encoding="utf-8")
    
    java_file = src_dir / "Sample.java"
    java_file.write_text(
        "package com.example;\n\npublic class Sample {\n    public void test() {\n        System.out.println(\"Hello\");\n    }\n}\n",
        encoding="utf-8"
    )
    return tmp_path

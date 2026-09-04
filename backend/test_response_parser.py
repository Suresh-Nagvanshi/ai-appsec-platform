from backend.ai.response_parser import ResponseParser

def test_response_parser():
    parser = ResponseParser()
    raw_response = """
    {
        "summary": "SQL Injection found",
        "attack_scenario": "Attacker injects SQL payload",
        "business_impact": "Data breach",
        "secure_fix": "Use prepared statements",
        "developer_remediation_steps": ["Use PreparedStatement"],
        "mitre_attack_mapping": ["T1190"]
    }
    """
    parsed = parser.parse(raw_response)
    assert parsed is not None
    assert parsed.get("summary") == "SQL Injection found"
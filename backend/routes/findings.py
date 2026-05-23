from fastapi import APIRouter, HTTPException

router = APIRouter(
    prefix="/findings",
    tags=["Findings"]
)


@router.get("")
def get_findings():
    """
    Temporary findings endpoint.

    Later this will:
    - fetch from PostgreSQL
    - apply tenant isolation
    - support pagination
    - support filtering
    - support RBAC
    """

    return [
        {
            "id": "1",
            "title": "SQL Injection vulnerability",
            "severity": "CRITICAL",
            "riskScore": 9.8,
            "exploitability": "Very High",
            "repository": "webgoat-api",
            "filePath": "src/api/users.ts",
            "status": "OPEN",
            "createdAt": "2026-05-14",
        },
        {
            "id": "2",
            "title": "Hardcoded JWT secret",
            "severity": "HIGH",
            "riskScore": 8.1,
            "exploitability": "High",
            "repository": "auth-service",
            "filePath": ".env",
            "status": "OPEN",
            "createdAt": "2026-05-14",
        },
        {
            "id": "3",
            "title": "Insecure deserialization",
            "severity": "MEDIUM",
            "riskScore": 6.5,
            "exploitability": "Medium",
            "repository": "payments-api",
            "filePath": "serializers.py",
            "status": "IN_PROGRESS",
            "createdAt": "2026-05-13",
        },
    ]

mock_findings = [
    {
        "id":"1",

        "title":"SQL Injection vulnerability",

        "severity":"CRITICAL",

        "riskScore":9.8,

        "exploitability":"Very High",

        "repository":"webgoat-api",

        "filePath":"src/api/users.ts",

        "framework":"Spring Boot",

        "status":"OPEN",

        "createdAt":"2026-05-14",

        "cwe":"CWE-89",

        "owasp":"A03:2021 Injection",

        "mitre":"T1190",

        "ai_summary":
        "Unsanitized user input reaches SQL query construction.",

        "attack_scenario":
        "An attacker can inject SQL payloads through user-controlled parameters and potentially dump or manipulate database records.",

        "business_impact":
        "Potential database compromise and unauthorized data access.",

        "secure_fix":
        "Use parameterized queries and input validation.",

        "developer_steps":[
            "Replace string concatenation",
            "Use prepared statements",
            "Validate input"
        ],

        "snippet":
        """SELECT * FROM users
WHERE id='${userInput}'"""
    }
]


@router.get("/{finding_id}")
def get_finding_details(
    finding_id: str
):

    finding = next(
        (
            f
            for f in mock_findings
            if f["id"] == finding_id
        ),
        None
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    return finding
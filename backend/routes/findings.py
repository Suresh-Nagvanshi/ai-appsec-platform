from fastapi import APIRouter

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
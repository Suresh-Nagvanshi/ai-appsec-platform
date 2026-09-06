"""Credential-free runtime and cloud security posture correlation API."""

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter()


class RuntimeAsset(BaseModel):
    asset_id: str
    name: str
    asset_type: str
    environment: str = "unknown"
    internet_exposed: bool = False
    encrypted: bool | None = None
    vulnerabilities: list[dict] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)


class RuntimePostureRequest(BaseModel):
    assets: list[RuntimeAsset] = Field(max_length=1_000)


def analyze_runtime_posture(assets: list[RuntimeAsset]) -> dict:
    findings = []
    for asset in assets:
        if asset.internet_exposed and asset.environment.lower() in {"prod", "production"}:
            findings.append({"asset_id": asset.asset_id, "severity": "HIGH", "rule": "internet-exposed-production", "message": "Production asset is internet-exposed and should have an explicit exposure review."})
        if asset.internet_exposed and asset.encrypted is False:
            findings.append({"asset_id": asset.asset_id, "severity": "HIGH", "rule": "unencrypted-exposed-asset", "message": "Internet-exposed asset does not report encryption at rest or in transit."})
        for vulnerability in asset.vulnerabilities:
            severity = str(vulnerability.get("severity", "INFO")).upper()
            if severity in {"CRITICAL", "HIGH"}:
                findings.append({"asset_id": asset.asset_id, "severity": severity, "rule": "runtime-vulnerability", "cve": vulnerability.get("cve"), "message": f"{severity} vulnerability is associated with runtime asset."})

    findings.sort(key=lambda item: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(item["severity"], 5), item["asset_id"]))
    return {
        "assets": [asset.model_dump() for asset in assets],
        "findings": findings,
        "summary": {
            "assets": len(assets),
            "internet_exposed": sum(asset.internet_exposed for asset in assets),
            "critical": sum(item["severity"] == "CRITICAL" for item in findings),
            "high": sum(item["severity"] == "HIGH" for item in findings),
        },
        "disclaimer": "This correlates supplied runtime evidence; it does not connect to cloud providers or verify live infrastructure without an approved integration.",
    }


@router.post("/posture")
def runtime_posture(payload: RuntimePostureRequest):
    return analyze_runtime_posture(payload.assets)

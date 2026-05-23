from fastapi import APIRouter
from pydantic import BaseModel
from uuid import uuid4

router = APIRouter()


class ScanRequest(BaseModel):
    repository_url: str


class ScanResponse(BaseModel):
    scan_id: str
    status: str

@router.post(
    "/start",
    response_model=ScanResponse
)
async def start_scan(payload: ScanRequest):

    scan_id = str(uuid4())

    return ScanResponse(
scan_id=scan_id,
status="QUEUED"
)
"""Controlled exploit-validation sandbox backed by Docker."""

import subprocess
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.api.api_security import _allowed_project_path

router = APIRouter()
_ALLOWED_IMAGES = {"python:3.12-slim", "node:22-alpine"}


class SandboxRequest(BaseModel):
    project_path: str
    command: list[str] = Field(min_length=1, max_length=16)
    image: str = "python:3.12-slim"
    timeout_seconds: int = Field(default=15, ge=1, le=60)


def validate_sandbox_request(project_path: Path, command: list[str], image: str, timeout_seconds: int) -> list[str]:
    if image not in _ALLOWED_IMAGES:
        raise HTTPException(status_code=400, detail="Image is not on the sandbox allowlist")
    if not command or any("\x00" in part for part in command):
        raise HTTPException(status_code=400, detail="Command must contain non-empty safe arguments")
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--memory", "256m", "--cpus", "0.5", "--pids-limit", "64",
        "--user", "65532:65532", "-v", f"{project_path}:/workspace:ro",
        "-w", "/workspace", image, *command,
    ]


def run_sandbox(project_path: Path, command: list[str], image: str, timeout_seconds: int) -> dict:
    docker_command = validate_sandbox_request(project_path, command, image, timeout_seconds)
    try:
        result = subprocess.run(
            docker_command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Docker is required for sandbox validation")
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "TIMEOUT",
            "exit_code": None,
            "stdout": (exc.stdout or "")[-4000:],
            "stderr": (exc.stderr or "")[-4000:],
            "docker_command": docker_command[:2] + ["[REDACTED_ARGS]"],
        }

    return {
        "status": "PASS" if result.returncode == 0 else "FAIL",
        "exit_code": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "docker_command": docker_command[:2] + ["[REDACTED_ARGS]"],
        "disclaimer": "Sandbox execution is evidence for this test case only; it does not prove a vulnerability is exploitable in production.",
    }


@router.post("/run")
async def sandbox_validation(payload: SandboxRequest):
    project_path = _allowed_project_path(payload.project_path)
    import asyncio
    return await asyncio.to_thread(
        run_sandbox,
        project_path,
        payload.command,
        payload.image,
        payload.timeout_seconds,
    )

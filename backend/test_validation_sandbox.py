from pathlib import Path

import pytest
from fastapi import HTTPException

from backend.api.validation_sandbox import run_sandbox, validate_sandbox_request


def test_sandbox_command_has_isolation_controls(tmp_path):
    command = validate_sandbox_request(tmp_path, ["python", "-c", "print(1)"], "python:3.12-slim", 10)

    assert "--network" in command
    assert "none" in command
    assert "--read-only" in command
    assert "--cap-drop" in command
    assert "--security-opt" in command
    assert "--memory" in command


def test_sandbox_rejects_unapproved_image(tmp_path):
    with pytest.raises(HTTPException):
        validate_sandbox_request(tmp_path, ["sh"], "alpine:latest", 10)


def test_sandbox_returns_execution_evidence(tmp_path, monkeypatch):
    class Result:
        returncode = 0
        stdout = "proof"
        stderr = ""

    monkeypatch.setattr("backend.api.validation_sandbox.subprocess.run", lambda *args, **kwargs: Result())
    report = run_sandbox(tmp_path, ["python", "-c", "print(1)"], "python:3.12-slim", 10)

    assert report["status"] == "PASS"
    assert report["stdout"] == "proof"

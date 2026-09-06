import base64

import pytest
from fastapi import HTTPException

from backend.api.fix import (
    PullRequestFixRequest,
    _github_repo_parts,
    _safe_relative_path,
    create_github_pull_request,
    generate_unified_diff,
    _local_fix,
)

def test_unified_diff_generator():
    vuln = "user_input = request.GET.get('id')\nquery = 'SELECT * FROM users WHERE id=' + user_input"
    sec = "user_input = request.GET.get('id')\ncursor.execute('SELECT * FROM users WHERE id=%s', (user_input,))"
    diff = generate_unified_diff(vuln, sec, "views.py")
    assert "--- a/views.py" in diff
    assert "+++ b/views.py" in diff
    assert "-query = 'SELECT * FROM users WHERE id=' + user_input" in diff
    assert "+cursor.execute('SELECT * FROM users WHERE id=%s', (user_input,))" in diff

def test_local_fix():
    finding = {
        "finding": {
            "extra": {"lines": "eval(user_input)", "message": "Avoid eval()"},
            "metadata": {"language": "python"}
        }
    }
    fix = _local_fix(finding)
    assert fix["language"] == "python"
    assert fix["vulnerable_code"] == "eval(user_input)"
    assert fix["ai_unavailable"] is True


def test_github_pull_request_workflow_uses_exact_replacement():
    class Response:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload

        def json(self):
            return self._payload

    class Client:
        def __init__(self):
            self.calls = []

        def get(self, path, **kwargs):
            self.calls.append(("GET", path))
            if "/git/ref/heads/" in path:
                return Response(200, {"object": {"sha": "base-sha"}})
            if "/contents/" in path:
                return Response(200, {
                    "sha": "file-sha",
                    "content": base64.b64encode(b"unsafe()\n").decode("ascii"),
                })
            return Response(200, {})

        def post(self, path, **kwargs):
            self.calls.append(("POST", path))
            if path.endswith("/pulls"):
                return Response(201, {"number": 42, "html_url": "https://github.com/o/r/pull/42", "state": "open"})
            return Response(201, {})

        def put(self, path, **kwargs):
            self.calls.append(("PUT", path))
            return Response(200, {})

    client = Client()
    result = create_github_pull_request(
        PullRequestFixRequest(
            repo_url="https://github.com/o/r",
            file_path="src/app.py",
            vulnerable_code="unsafe()",
            secure_code="safe()",
        ),
        "token",
        client=client,
    )

    assert result["pull_request"]["number"] == 42
    assert "-unsafe()" in result["diff_patch"]
    assert [call[0] for call in client.calls] == ["GET", "GET", "GET", "POST", "PUT", "POST"]


def test_github_fix_rejects_unsafe_paths_and_urls():
    with pytest.raises(HTTPException):
        _github_repo_parts("https://evil.example/o/r")
    with pytest.raises(HTTPException):
        _safe_relative_path("../secrets.txt")

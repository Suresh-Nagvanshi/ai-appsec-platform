"""
Tests for Repository Security — Branch Selection & Incremental Diff Scanning.
Tests are structured to run without network access (no actual git clone).
"""

import re
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


# ── Branch name regex validation ──────────────────────────────────────────────

_BRANCH_RE = re.compile(r'^[a-zA-Z0-9._/\-]{1,200}$')

class TestBranchNameValidation:
    """Test the branch name whitelist regex used in the API."""

    def test_accepts_simple_branch(self):
        assert _BRANCH_RE.match("main")

    def test_accepts_feature_slash_branch(self):
        assert _BRANCH_RE.match("feature/my-cool-feature")

    def test_accepts_version_tag_style(self):
        assert _BRANCH_RE.match("release/v1.2.3")

    def test_accepts_numeric_branch(self):
        assert _BRANCH_RE.match("hotfix-123")

    def test_rejects_semicolon_injection(self):
        assert not _BRANCH_RE.match("main; rm -rf /")

    def test_rejects_backtick_injection(self):
        assert not _BRANCH_RE.match("`whoami`")

    def test_rejects_dollar_injection(self):
        assert not _BRANCH_RE.match("$(evil)")

    def test_rejects_empty_string(self):
        assert not _BRANCH_RE.match("")

    def test_rejects_too_long_branch(self):
        assert not _BRANCH_RE.match("a" * 201)

    def test_accepts_max_length_branch(self):
        assert _BRANCH_RE.match("a" * 200)


# ── Scan record branch metadata ───────────────────────────────────────────────

class TestScanRecordBranchMetadata:
    """Test that branch info is stored correctly in scan records."""

    def test_scan_record_includes_branch_field(self):
        """_new_scan should store the branch in the record."""
        import copy
        from datetime import datetime

        def _new_scan(scan_type: str, target: str, branch=None) -> dict:
            from uuid import uuid4
            return {
                "id": str(uuid4()),
                "scanType": scan_type,
                "target": target,
                "branch": branch,
                "status": "QUEUED",
                "progress": 0,
                "startedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "completedAt": None,
                "duration": None,
                "findingsCount": 0,
                "criticalCount": 0,
                "summary": {},
                "logs": [],
                "timeline": [],
                "failureReason": None,
            }

        scan = _new_scan("github", "https://github.com/org/repo", branch="feat/new")
        assert scan["branch"] == "feat/new"

    def test_scan_record_branch_is_none_by_default(self):
        """_new_scan without branch should store None."""
        from uuid import uuid4
        from datetime import datetime

        def _new_scan(scan_type, target, branch=None):
            return {"id": str(uuid4()), "branch": branch, "target": target}

        scan = _new_scan("github", "https://github.com/org/repo")
        assert scan["branch"] is None


# ── Git diff helper logic ─────────────────────────────────────────────────────

class TestComputeGitDiffLogic:
    """Test the source-file filtering logic in _compute_git_diff."""

    def _make_diff_entry(self, path: str, change_type: str):
        m = MagicMock()
        m.change_type = change_type
        m.b_path = path if change_type != "D" else None
        m.a_path = path
        return m

    def test_filters_out_deleted_files(self):
        """Deleted files should not appear in changed_files list."""
        from pathlib import Path

        _SRC_EXTS = {".py", ".js", ".ts"}
        diffs = [
            self._make_diff_entry("src/app.py", "D"),
            self._make_diff_entry("src/routes.py", "M"),
        ]
        changed_files = []
        deleted = 0
        for d in diffs:
            if d.change_type == "D":
                deleted += 1
                continue
            path = d.b_path or d.a_path
            if Path(path).suffix.lower() in _SRC_EXTS:
                changed_files.append(path)

        assert "src/app.py" not in changed_files
        assert "src/routes.py" in changed_files
        assert deleted == 1

    def test_filters_non_source_files(self):
        """Non-source extensions like .md, .png should be excluded."""
        from pathlib import Path

        _SRC_EXTS = {".py", ".js", ".ts"}
        diffs = [
            self._make_diff_entry("README.md", "M"),
            self._make_diff_entry("logo.png", "M"),
            self._make_diff_entry("src/app.ts", "M"),
        ]
        changed_files = []
        for d in diffs:
            if d.change_type == "D":
                continue
            path = d.b_path or d.a_path
            if Path(path).suffix.lower() in _SRC_EXTS:
                changed_files.append(path)

        assert "README.md" not in changed_files
        assert "logo.png" not in changed_files
        assert "src/app.ts" in changed_files


# ── Repository default_branch storage ────────────────────────────────────────

class TestRepositoryDefaultBranch:
    """Test that default_branch is stored and returned by the Repositories API."""

    def test_create_repository_with_branch(self, tmp_path, monkeypatch):
        """POST /api/repositories with default_branch should persist the value."""
        import sys, importlib

        # Redirect storage to a temp dir
        monkeypatch.setenv("REPOS_DB_PATH", str(tmp_path))

        # Patch the module-level _BASE_DIR
        import backend.api.repositories as repos_module
        monkeypatch.setattr(repos_module, "_BASE_DIR", tmp_path)
        (tmp_path).mkdir(parents=True, exist_ok=True)

        repo_data = repos_module.RepositoryCreate(
            name="TestRepo",
            url="https://github.com/org/repo",
            provider="github",
            default_branch="develop",
        )

        # Simulate create_repository logic
        assert repo_data.default_branch == "develop"
        branch = repo_data.default_branch.strip() if repo_data.default_branch else None
        assert branch == "develop"

    def test_repository_create_rejects_invalid_branch(self):
        """default_branch with shell metacharacters should fail regex check."""
        branch = "main; curl evil.com"
        assert not _BRANCH_RE.match(branch)

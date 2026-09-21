"""Lightweight source-to-sink reachability analysis.

This analyzer is deliberately conservative. It uses framework entry points,
common user-input sources, dangerous sinks, and local function boundaries to
produce an explainable signal for prioritization. It is not a replacement for
language-specific taint analysis.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional


class ReachabilityAnalyzer:
    SOURCE_PATTERNS = {
        "http_request": re.compile(r"\b(request\.(args|form|json|GET|POST|query|query_params|body|headers|cookies)|req\.(body|query|params|headers)|ctx\.request)\b", re.I),
        "route_parameter": re.compile(r"(@PathVariable|@RequestParam|<int:[^>]+>|\{[^}]+\})"),
        "stdin": re.compile(r"\b(input\(|sys\.stdin|process\.stdin)\b"),
    }
    SINK_PATTERNS = {
        "sql_query": re.compile(r"\b(executeQuery|executeUpdate|[A-Za-z_][A-Za-z0-9_]*\.execute|raw|query)\s*\(", re.I),
        "command_execution": re.compile(r"\b(eval\(|exec\(|os\.system|subprocess\.|ProcessBuilder|Runtime\.getRuntime)\b", re.I),
        "file_write": re.compile(r"\b(open\([^\n]*(['\"]w|mode\s*=\s*['\"]w)|write_text\(|writeFile\()", re.I),
        "template_render": re.compile(r"\b(render_template|render\(|innerHTML\s*=|dangerouslySetInnerHTML)\b", re.I),
        "outbound_request": re.compile(r"\b(requests\.(get|post|put|delete)|axios\.(get|post|put|delete)|fetch\()", re.I),
        "deserialization": re.compile(r"\b(pickle\.loads|yaml\.load\(|ObjectInputStream|unserialize\()", re.I),
    }
    FUNCTION_PATTERN = re.compile(r"(?:def\s+|function\s+|(?:public|private|protected|static|async)\s+[\w<>\[\]]+\s+)([A-Za-z_][\w]*)\s*\(")
    CALL_PATTERN = re.compile(r"\b([A-Za-z_][\w]*)\s*\(")
    MAX_FILES = 5000
    MAX_FILE_BYTES = 1_000_000

    def analyze(self, project_path: str, finding: dict, endpoints: Optional[list[dict]] = None) -> dict:
        project = Path(project_path).resolve()
        relative_path = str(finding.get("path") or "").replace("\\", "/")
        target_path = Path(relative_path)
        if not target_path.is_absolute():
            target_path = project / target_path
        target_path = target_path.resolve()
        line_number = int(finding.get("line") or 1)

        if not target_path.exists() or not target_path.is_file():
            return self._unknown("Finding source file is unavailable for reachability analysis.")
        try:
            target_path.relative_to(project)
        except ValueError:
            return self._unknown("Finding source file is outside the managed project root.")

        source_hits: list[dict] = []
        sink_hits: list[dict] = []
        entry_points = []
        files_scanned = 0
        for path in project.rglob("*"):
            if files_scanned >= self.MAX_FILES or not path.is_file() or path.stat().st_size > self.MAX_FILE_BYTES:
                continue
            if any(part in {".git", "node_modules", ".venv", "venv", "dist", "build", "target"} for part in path.parts):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_scanned += 1
            relative = path.relative_to(project).as_posix()
            for number, text in enumerate(content.splitlines(), 1):
                for source_name, pattern in self.SOURCE_PATTERNS.items():
                    if pattern.search(text):
                        source_hits.append({"type": source_name, "file": relative, "line": number, "evidence": text.strip()[:160]})
                for sink_name, pattern in self.SINK_PATTERNS.items():
                    if pattern.search(text):
                        sink_hits.append({"type": sink_name, "file": relative, "line": number, "evidence": text.strip()[:160]})

        for endpoint in endpoints or []:
            endpoint_file = str(endpoint.get("file") or "")
            try:
                endpoint_relative = Path(endpoint_file).resolve().relative_to(project).as_posix()
            except (ValueError, OSError):
                endpoint_relative = endpoint_file.replace("\\", "/")
            entry_points.append({**endpoint, "file": endpoint_relative})

        target_relative = target_path.relative_to(project).as_posix()
        relevant_sources = [item for item in source_hits if item["file"] == target_relative and item["line"] <= line_number]
        relevant_sinks = [item for item in sink_hits if item["file"] == target_relative]
        related_entries = [item for item in entry_points if item.get("file") == target_relative]
        function_name = self._function_at_line(target_path, line_number)
        same_function_source = self._same_function_source(target_path, line_number, function_name, relevant_sources)
        sink_at_finding = any(item["line"] <= line_number + 2 and item["line"] >= line_number - 2 for item in relevant_sinks)

        if same_function_source and sink_at_finding:
            status = "reachable"
            score = 0.95
            reason = "A recognized user-controlled source occurs before a dangerous sink in the same function."
        elif related_entries and sink_at_finding:
            status = "reachable"
            score = 0.85
            reason = "A discovered HTTP entry point maps to the finding file and contains a recognized sink."
        elif not relevant_sinks:
            status = "unknown"
            score = 0.35
            reason = "No recognized sink was found near the reported location."
        else:
            status = "not_reachable"
            score = 0.2
            reason = "A sink was found, but no preceding source or mapped entry point was identified."

        path = []
        if related_entries:
            first = related_entries[0]
            path.append({"kind": "entry_point", "method": first.get("method"), "endpoint": first.get("endpoint"), "file": target_relative})
        if relevant_sources:
            path.append({"kind": "source", "type": relevant_sources[-1]["type"], "file": target_relative, "line": relevant_sources[-1]["line"]})
        if relevant_sinks:
            path.append({"kind": "sink", "type": relevant_sinks[0]["type"], "file": target_relative, "line": relevant_sinks[0]["line"]})

        return {
            "status": status,
            "score": score,
            "confidence": score,
            "reason": reason,
            "entry_points": related_entries,
            "sources": relevant_sources,
            "sinks": relevant_sinks,
            "path": path,
            "function": function_name,
            "files_scanned": files_scanned,
        }

    def _function_at_line(self, path: Path, line_number: int) -> Optional[str]:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return None
        current = None
        for number, text in enumerate(lines, 1):
            match = self.FUNCTION_PATTERN.search(text)
            if match:
                current = match.group(1)
            if number >= line_number:
                break
        return current

    def _same_function_source(self, path: Path, line_number: int, function_name: Optional[str], sources: list[dict]) -> bool:
        if not sources:
            return False
        if function_name is None:
            return any(item["line"] < line_number for item in sources)
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return False
        start = 1
        for number, text in enumerate(lines, 1):
            match = self.FUNCTION_PATTERN.search(text)
            if match and match.group(1) == function_name:
                start = number
            if number >= line_number:
                break
        return any(start <= item["line"] < line_number for item in sources)

    @staticmethod
    def _unknown(reason: str) -> dict:
        return {"status": "unknown", "score": 0.35, "confidence": 0.35, "reason": reason, "entry_points": [], "sources": [], "sinks": [], "path": [], "function": None, "files_scanned": 0}

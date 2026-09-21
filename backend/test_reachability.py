from backend.enrichment.context_builder import ContextBuilder
from backend.enrichment.reachability import ReachabilityAnalyzer
from backend.risk.risk_scorer import RiskScorer


def test_reachability_detects_source_to_sql_sink(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n"
        "@app.get('/users')\n"
        "async def users(request: Request):\n"
        "    username = request.query_params.get('username')\n"
        "    return db.execute('SELECT * FROM users WHERE name=' + username)\n",
        encoding="utf-8",
    )

    result = ReachabilityAnalyzer().analyze(
        str(tmp_path),
        {"path": "app.py", "line": 6},
        [{"framework": "FastAPI", "method": "GET", "endpoint": "/users", "file": str(source)}],
    )

    assert result["status"] == "reachable"
    assert result["sources"]
    assert result["sinks"]
    assert result["entry_points"][0]["endpoint"] == "/users"


def test_context_and_risk_include_reachability(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def run(value):\n    return eval(value)\n", encoding="utf-8")
    raw = {"check_id": "python.eval", "path": "app.py", "start": {"line": 2}, "extra": {"severity": "HIGH", "message": "Unsafe eval", "metadata": {"cwe": ["CWE-95"]}}}

    context = ContextBuilder().build(raw, str(tmp_path))
    risk = RiskScorer().calculate(context)

    assert context["reachability"]["status"] in {"unknown", "not_reachable"}
    assert "reachability" in risk

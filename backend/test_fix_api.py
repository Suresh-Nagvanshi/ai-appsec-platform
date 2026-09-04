from backend.api.fix import generate_unified_diff, _local_fix

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

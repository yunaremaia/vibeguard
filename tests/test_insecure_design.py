"""Behavioural tests for the Insecure Design rules (OWASP A04:2021).

Each rule gets a positive case, a negative case that must stay silent, and a
location assertion (line/column) so an off-by-one offset cannot pass.
"""

from pathlib import Path

from vibeguard.rules import insecure_design
from vibeguard.scanner import scan_file as scan_all_rules


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def rule_ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# VGB-020 — sensitive operation without an authorization check
# ---------------------------------------------------------------------------


def test_sensitive_handler_without_authorization(tmp_path):
    source = (
        'from flask import Flask\n'
        'app = Flask(__name__)\n'
        '@app.route("/users/<uid>", methods=["DELETE"])\n'
        'def delete_user(uid):\n'
        '    db.delete(uid)\n'
        '    return "gone"\n'
    )
    findings = insecure_design.scan_file(write(tmp_path, "app.py", source))
    assert rule_ids(findings) == ["VGB-020"]
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 4
    assert findings[0].column == 1
    assert findings[0].snippet.startswith("def delete_user")
    assert "permission" in findings[0].fix_hint


def test_sensitive_handler_with_authorization_is_silent(tmp_path):
    source = (
        '@app.route("/users/<uid>", methods=["DELETE"])\n'
        "@login_required\n"
        'def delete_user(uid):\n'
        '    check_permission("users.delete")\n'
        '    db.delete(uid)\n'
    )
    assert insecure_design.scan_file(write(tmp_path, "app.py", source)) == []


# ---------------------------------------------------------------------------
# VGB-021 — API endpoint without rate limiting
# ---------------------------------------------------------------------------


def test_api_route_without_rate_limit(tmp_path):
    source = '@app.get("/api/items")\ndef list_items():\n    return []\n'
    findings = insecure_design.scan_file(write(tmp_path, "api.py", source))
    assert rule_ids(findings) == ["VGB-021"]
    assert findings[0].severity == "MEDIUM"
    assert findings[0].line == 1
    assert findings[0].column == 1
    assert "rate limit" in findings[0].fix_hint


def test_api_route_with_rate_limit_is_silent(tmp_path):
    source = (
        '@app.get("/api/items")\n'
        "@limiter.limit(\"10 per minute\")\n"
        "def list_items():\n"
        "    return []\n"
    )
    assert insecure_design.scan_file(write(tmp_path, "api.py", source)) == []


# ---------------------------------------------------------------------------
# VGB-022 — unvalidated user input reaching a sensitive sink
# ---------------------------------------------------------------------------


def test_request_argument_flows_into_sql(tmp_path):
    source = 'def run():\n    sql = request.args.get("q")\n    cursor.execute(sql)\n'
    findings = insecure_design.scan_file(write(tmp_path, "q.py", source))
    assert rule_ids(findings) == ["VGB-022"]
    assert findings[0].severity == "CRITICAL"
    assert findings[0].line == 2
    assert findings[0].column == 11
    assert "validate" in findings[0].fix_hint.lower()


def test_validated_input_is_silent(tmp_path):
    source = (
        "def run():\n"
        '    name = request.args.get("name")\n'
        "    name = sanitize(name)\n"
        "    cursor.execute(name)\n"
    )
    assert insecure_design.scan_file(write(tmp_path, "q.py", source)) == []


# ---------------------------------------------------------------------------
# VGB-023 — insecure default configuration
# ---------------------------------------------------------------------------


def test_insecure_defaults(tmp_path):
    source = (
        "VERIFY_SSL = False\n"
        "SESSION_COOKIE_SECURE = False\n"
        'app.run(host="0.0.0.0")\n'
    )
    findings = insecure_design.scan_file(write(tmp_path, "settings.py", source))
    assert rule_ids(findings) == ["VGB-023"] * 3
    assert [(f.line, f.column) for f in findings] == [(1, 1), (2, 1), (3, 9)]
    assert findings[0].severity == "HIGH"


# ---------------------------------------------------------------------------
# VGB-024 — state transition without a precondition check
# ---------------------------------------------------------------------------


def test_state_transition_without_state_check(tmp_path):
    source = (
        "def approve_order(order_id):\n"
        "    order = orders.get(order_id)\n"
        '    order.status = "approved"\n'
        "    save(order)\n"
    )
    findings = insecure_design.scan_file(write(tmp_path, "orders.py", source))
    assert rule_ids(findings) == ["VGB-024"]
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 1
    assert findings[0].column == 1
    assert "state" in findings[0].fix_hint


def test_state_transition_with_state_check_is_silent(tmp_path):
    source = (
        "def cancel_order(order_id):\n"
        "    order = orders.get(order_id)\n"
        '    if order.status != "pending":\n'
        '        raise ValueError("not cancellable")\n'
        "    save(order)\n"
    )
    assert insecure_design.scan_file(write(tmp_path, "orders.py", source)) == []


# ---------------------------------------------------------------------------
# VGB-025 — response built without security headers
# ---------------------------------------------------------------------------


def test_response_without_security_headers(tmp_path):
    source = '@app.get("/home")\ndef home():\n    return Response("hi")\n'
    findings = insecure_design.scan_file(write(tmp_path, "views.py", source))
    assert rule_ids(findings) == ["VGB-025"]
    assert findings[0].severity == "MEDIUM"
    assert findings[0].line == 3
    assert findings[0].column == 12
    assert "Content-Security-Policy" in findings[0].fix_hint


def test_response_with_security_headers_is_silent(tmp_path):
    source = (
        '@app.get("/home")\n'
        "def home():\n"
        '    return Response("hi", headers={"Content-Security-Policy": "default-src \'self\'"})\n'
    )
    assert insecure_design.scan_file(write(tmp_path, "views.py", source)) == []


# ---------------------------------------------------------------------------
# Shared behaviour
# ---------------------------------------------------------------------------


def test_guarded_handler_file_is_clean(tmp_path):
    """One file where every A04 guard is present: the rules must stay silent."""
    source = (
        '@app.get("/api/orders")\n'
        "@login_required\n"
        '@limiter.limit("10 per minute")\n'
        "def list_orders():\n"
        "    query = validate(request.args.get(\"q\"))\n"
        "    rows = cursor.execute(query)\n"
        "    if not rows.status:\n"
        "        return error()\n"
        '    return Response("ok", headers={"Content-Security-Policy": "default-src \'self\'"})\n'
    )
    assert insecure_design.scan_file(write(tmp_path, "orders.py", source)) == []


def test_comments_are_not_flagged(tmp_path):
    source = "# def delete_user(uid): db.delete(uid)\n// app.run(host=\"0.0.0.0\")\n"
    assert insecure_design.scan_file(write(tmp_path, "notes.py", source)) == []


def test_unreadable_file_yields_no_findings(tmp_path):
    """A missing file makes read_text raise OSError; the rule must not."""
    assert insecure_design.scan_file(tmp_path / "gone.py") == []


def test_long_line_snippet_is_truncated(tmp_path):
    source = "def delete_user(uid):  # " + "x" * 200 + "\n"
    findings = insecure_design.scan_file(write(tmp_path, "app.py", source))
    assert findings[0].snippet.endswith("...")
    assert len(findings[0].snippet) == 123


def test_all_insecure_design_rules_fire_through_the_scanner(tmp_path):
    source = (
        '@app.route("/api/orders/<oid>/approve", methods=["POST"])\n'
        "def approve_order(oid):\n"
        '    sql = request.args.get("q")\n'
        "    cursor.execute(sql)\n"
        "    order = orders.get(oid)\n"
        '    order.status = "approved"\n'
        "    save(order)\n"
        '    return Response("ok")\n'
        "\n"
        "\n"
        "def delete_order(oid):\n"
        "    db.delete(oid)\n"
    )
    findings = scan_all_rules(write(tmp_path, "orders.py", source))
    found = {f.rule_id for f in findings}
    assert {"VGB-020", "VGB-021", "VGB-022", "VGB-024", "VGB-025"} <= found
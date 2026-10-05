"""Behavioural tests for the Insecure Client-Side rules (OWASP A05:2021).

Each check gets a positive case, a negative case that must stay silent, and a
location assertion (line/column) so an off-by-one offset cannot pass.
"""

from pathlib import Path

from vibeguard.rules import client_side
from vibeguard.scanner import scan_file as scan_all_rules


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def rule_ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# innerHTML / outerHTML / insertAdjacentHTML XSS sink
# ---------------------------------------------------------------------------


def test_innerhtml_with_variable_is_flagged(tmp_path):
    source = "function render(userInput) {\n    el.innerHTML = userInput;\n}\n"
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    assert rule_ids(findings) == ["VGB-030"]
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 2
    assert findings[0].column == 5
    assert "innerHTML" in findings[0].message
    assert "textContent" in findings[0].fix_hint


def test_outerhtml_with_template_literal_is_flagged(tmp_path):
    source = "el.outerHTML = `<b>${name}</b>`;\n"
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    assert rule_ids(findings) == ["VGB-030"]
    assert findings[0].line == 1
    assert "outerHTML" in findings[0].message


def test_insert_adjacent_html_with_concatenation_is_flagged(tmp_path):
    source = "el.insertAdjacentHTML('beforeend', markup + suffix);\n"
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    assert rule_ids(findings) == ["VGB-030"]
    assert findings[0].line == 1
    assert "insertAdjacentHTML" in findings[0].message


def test_html_sink_with_plain_literal_is_silent(tmp_path):
    source = "el.innerHTML = '<b>static</b>';\n"
    assert client_side.scan_file(write(tmp_path, "app.js", source)) == []


def test_comparison_to_literal_is_not_a_sink(tmp_path):
    source = "if (el.innerHTML === '<b>ok</b>') { render(); }\n"
    assert client_side.scan_file(write(tmp_path, "app.js", source)) == []


def test_one_finding_per_sink_line(tmp_path):
    """A single line must never produce the same finding twice."""
    source = "el.innerHTML = a; el.outerHTML = b; el.innerHTML += c;\n"
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    assert len(findings) == 1
    assert findings[0].line == 1


# ---------------------------------------------------------------------------
# document.write
# ---------------------------------------------------------------------------


def test_document_write_with_variable_is_flagged(tmp_path):
    source = "document.write(userSupplied);\n"
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    assert rule_ids(findings) == ["VGB-030"]
    assert findings[0].line == 1
    assert findings[0].column == 1
    assert "document.write" in findings[0].message


def test_document_write_with_literal_is_silent(tmp_path):
    assert client_side.scan_file(write(tmp_path, "app.js", "document.write('<p>hi</p>');\n")) == []


# ---------------------------------------------------------------------------
# postMessage without an origin check
# ---------------------------------------------------------------------------


def test_post_message_listener_without_origin_check_is_flagged(tmp_path):
    source = (
        "window.addEventListener('message', (event) => {\n"
        "    document.getElementById('out').innerHTML = event.data;\n"
        "});\n"
    )
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    # Two real sinks: the unguarded listener on line 1 and the innerHTML sink
    # fed by event.data on line 2.
    assert len(findings) == 2
    origin = [f for f in findings if "origin" in f.message]
    assert len(origin) == 1
    assert origin[0].line == 1
    assert origin[0].severity == "HIGH"
    assert "event.origin" in origin[0].fix_hint


def test_message_listener_with_origin_check_is_silent(tmp_path):
    source = (
        "window.addEventListener('message', (event) => {\n"
        "    if (event.origin !== 'https://trusted.example') return;\n"
        "    handle(event.data);\n"
        "});\n"
    )
    assert client_side.scan_file(write(tmp_path, "app.js", source)) == []


def test_post_message_send_to_wildcard_target_is_flagged(tmp_path):
    source = "iframe.contentWindow.postMessage(payload, '*');\n"
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    assert rule_ids(findings) == ["VGB-030"]
    assert findings[0].line == 1
    assert findings[0].severity == "MEDIUM"
    assert findings[0].message == "postMessage() sent to a wildcard target origin"


def test_post_message_send_to_explicit_origin_is_silent(tmp_path):
    source = "iframe.contentWindow.postMessage(payload, 'https://trusted.example');\n"
    assert client_side.scan_file(write(tmp_path, "app.js", source)) == []


# ---------------------------------------------------------------------------
# Secret written to web storage
# ---------------------------------------------------------------------------


def test_secret_written_to_local_storage_is_flagged(tmp_path):
    source = "localStorage.setItem('api_key', 'sk_live_51H8xQ2eZvKYlo2C');\n"
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    assert rule_ids(findings) == ["VGB-030"]
    assert findings[0].line == 1
    assert findings[0].severity == "HIGH"
    assert "localStorage" in findings[0].message


def test_secret_assigned_to_session_storage_is_flagged(tmp_path):
    source = "sessionStorage.authToken = 'eyJhbGciOiJIUzI1NiJ9';\n"
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    assert rule_ids(findings) == ["VGB-030"]
    assert findings[0].line == 1
    assert "sessionStorage" in findings[0].message


def test_non_secret_written_to_local_storage_is_silent(tmp_path):
    source = "localStorage.setItem('theme', 'dark');\n"
    assert client_side.scan_file(write(tmp_path, "app.js", source)) == []


def test_storage_write_of_a_variable_is_silent(tmp_path):
    """The rule matches the literal, never a variable name — no secret value here."""
    source = "localStorage.setItem('theme', userTheme);\n"
    assert client_side.scan_file(write(tmp_path, "app.js", source)) == []


def test_storage_read_is_silent(tmp_path):
    source = "const token = localStorage.getItem('api_key');\n"
    assert client_side.scan_file(write(tmp_path, "app.js", source)) == []


# ---------------------------------------------------------------------------
# target="_blank" without rel="noopener"
# ---------------------------------------------------------------------------


def test_target_blank_without_noopener_is_flagged(tmp_path):
    source = '<a href="/next" target="_blank">Next</a>\n'
    findings = client_side.scan_file(write(tmp_path, "app.html", source))
    assert rule_ids(findings) == ["VGB-030"]
    assert findings[0].line == 1
    assert findings[0].severity == "MEDIUM"
    assert "noopener" in findings[0].fix_hint


def test_target_blank_with_noopener_is_silent(tmp_path):
    source = '<a href="/next" target="_blank" rel="noopener">Next</a>\n'
    assert client_side.scan_file(write(tmp_path, "app.html", source)) == []


def test_target_blank_with_noopener_on_the_next_line_is_silent(tmp_path):
    source = '<a href="/next"\n   target="_blank"\n   rel="noreferrer noopener">Next</a>\n'
    assert client_side.scan_file(write(tmp_path, "app.html", source)) == []


# ---------------------------------------------------------------------------
# Shared behaviour
# ---------------------------------------------------------------------------


def test_hardened_file_is_clean(tmp_path):
    """One file where every A05 control is present: the rules must stay silent."""
    source = (
        "const el = document.getElementById('out');\n"
        "el.textContent = model.reply;\n"
        "el.innerHTML = '<br>';\n"
        "document.write('<p>static</p>');\n"
        "window.addEventListener('message', (event) => {\n"
        "    if (event.origin !== 'https://trusted.example') return;\n"
        "    handle(event.data);\n"
        "});\n"
        "frame.contentWindow.postMessage(data, 'https://trusted.example');\n"
        "localStorage.setItem('theme', 'dark');\n"
        '<a href="/next" target="_blank" rel="noopener">Next</a>\n'
    )
    assert client_side.scan_file(write(tmp_path, "app.js", source)) == []


def test_comments_are_not_flagged(tmp_path):
    source = (
        "// el.innerHTML = userInput;\n"
        "<!-- <a href='/x' target='_blank'>x</a> -->\n"
        "/* document.write(userInput); */\n"
    )
    assert client_side.scan_file(write(tmp_path, "notes.js", source)) == []


def test_unreadable_file_yields_no_findings(tmp_path):
    """A missing file makes read_text raise OSError; the rule must not."""
    assert client_side.scan_file(tmp_path / "gone.js") == []


def test_long_line_snippet_is_truncated(tmp_path):
    source = "el.innerHTML = userInput; // " + "x" * 400 + "\n"
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    assert findings[0].snippet.endswith("...")
    assert len(findings[0].snippet) == 123


def test_malformed_source_does_not_raise(tmp_path):
    """Unparseable-looking junk must be skipped, never crash the scan.

    A None tag or an unexpected node shape must not raise out of the rule —
    the whole scan used to die on a single weird file.
    """
    source = (
        "el.innerHTML = \x00;\n"
        "`unterminated template ${x\n"
        "<<>><>><\n"
        "\\x\n"
        "a\"b'c`d\n"
    )
    assert isinstance(client_side.scan_file(write(tmp_path, "weird.js", source)), list)


def test_a_raising_match_is_skipped_and_the_scan_continues(tmp_path, monkeypatch):
    """One bad line must be skipped, not abort the file or the scan.

    A None tag or an unexpected node shape killed the whole scan before: the
    exception was swallowed somewhere else and 38 detectors produced no output.
    """
    real = client_side._matches

    def exploding(lines, index, line):
        if index == 1:
            raise TypeError("simulated malformed node")
        yield from real(lines, index, line)

    monkeypatch.setattr(client_side, "_matches", exploding)
    source = "el.innerHTML = a;\nel.outerHTML = b;\nel.innerHTML = c;\n"
    findings = client_side.scan_file(write(tmp_path, "app.js", source))
    # Line 2 raised and was skipped; lines 1 and 3 still report, so one bad
    # line costs exactly one finding and not the whole scan.
    assert [(f.rule_id, f.line) for f in findings] == [("VGB-030", 1), ("VGB-030", 3)]


def test_all_client_side_rules_fire_through_the_scanner(tmp_path):
    source = (
        "el.innerHTML = userInput;\n"
        "document.write(userInput);\n"
        "window.addEventListener('message', (e) => { handle(e.data); });\n"
        "frame.contentWindow.postMessage(data, '*');\n"
        "localStorage.setItem('api_key', 'sk_live_51H8xQ2eZvKYlo2C');\n"
        '<a href="/next" target="_blank">Next</a>\n'
    )
    findings = scan_all_rules(write(tmp_path, "app.js", source))
    found = rule_ids(findings)
    assert found.count("VGB-030") == 6

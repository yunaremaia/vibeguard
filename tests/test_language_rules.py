"""Behavioural tests for the multi-language rules (Go, Rust, Java, Ruby).

These are the language patterns from #56. Like the category rules they are gated
to their file extensions so the idioms do not fire in unrelated languages, so
every test drives the real ``scan_file`` entry point through a real on-disk file
and asserts the rule id, severity, and the false-positive guards that keep the
scanner usable (extension gate, missing file, commented lines, the ReDoS line
cap, and snippet truncation).
"""

from pathlib import Path

import pytest

from vibeguard.rules import go_rules, java_rules, rust_rules, ruby_rules


def rule_ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# VGB-060 — Go
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "source", "severity"),
    [
        ("command_injection", 'exec.Command("sh", fmt.Sprintf("-c %s", input))\n', "CRITICAL"),
        ("ssrf", 'resp, _ := http.Get(fmt.Sprintf("http://%s", host))\n', "HIGH"),
        ("dsn", 'db, _ := sql.Open("mysql", fmt.Sprintf("user@tcp(%s)", dsn))\n', "HIGH"),
        ("sql_injection", 'rows, _ := db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%d", id))\n', "CRITICAL"),
    ],
)
def test_go_flags_each_injection_pattern(tmp_path, label, source, severity):
    path = tmp_path / f"{label}.go"
    path.write_text(source, encoding="utf-8")
    findings = go_rules.scan_file(path)
    assert [f.rule_id for f in findings] == ["VGB-060"], label
    assert findings[0].severity == severity
    assert findings[0].line == 1
    assert "injection" in findings[0].message or "SSRF" in findings[0].message or "DSN" in findings[0].message


def test_go_safe_idioms_are_not_reported(tmp_path):
    """A call on a plain quoted constant is the safe idiom and must not fire."""
    path = tmp_path / "safe.go"
    path.write_text(
        'exec.Command("ls", "-l")\n'
        'resp, _ := http.Get("https://api.example.com")\n'
        "db, _ := sql.Open(\"postgres\", dsn)\n"
        'rows, _ := db.Query("SELECT * FROM t WHERE id = $1", id)\n',
        encoding="utf-8",
    )
    assert go_rules.scan_file(path) == []


def test_go_rule_ignores_non_go_files(tmp_path):
    """The extension gate keeps Go idioms from firing in other languages."""
    path = tmp_path / "app.py"
    path.write_text('exec.Command("sh", fmt.Sprintf("-c %s", input))\n', encoding="utf-8")
    assert go_rules.scan_file(path) == []


def test_go_rule_returns_no_findings_for_missing_file(tmp_path):
    assert go_rules.scan_file(tmp_path / "gone.go") == []


def test_go_rule_ignores_commented_lines(tmp_path):
    path = tmp_path / "c.go"
    path.write_text('// exec.Command("sh", fmt.Sprintf("-c %s", input))\n', encoding="utf-8")
    assert go_rules.scan_file(path) == []


def test_go_rule_ignores_calls_past_the_line_length_limit(tmp_path):
    """The ReDoS guard truncates the line before matching."""
    limit = go_rules.MAX_LINE_LENGTH
    source = "x" * (limit + 10) + 'exec.Command("sh", fmt.Sprintf("-c %s", input))\n'
    target = tmp_path / "min.go"
    target.write_text(source, encoding="utf-8")
    assert go_rules.scan_file(target) == []


def test_go_rule_truncates_long_snippet_in_output(tmp_path):
    line = 'exec.Command("sh", fmt.Sprintf("-c %s", input))  // ' + "y" * 200 + "\n"
    path = tmp_path / "long.go"
    path.write_text(line, encoding="utf-8")
    finding = go_rules.scan_file(path)[0]
    assert len(finding.snippet) == 123
    assert finding.snippet.endswith("...")


# ---------------------------------------------------------------------------
# VGB-070 — Rust
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "source", "severity"),
    [
        ("unsafe_block", "fn f() { unsafe { ptr.write(42) } }\n", "MEDIUM"),
        ("command_injection", 'let c = std::process::Command::new("sh").arg(format!("-c {}", cmd)).output();\n', "CRITICAL"),
        ("unwrap_on_user", "let value = user_value.unwrap();\n", "HIGH"),
    ],
)
def test_rust_flags_each_pattern(tmp_path, label, source, severity):
    path = tmp_path / f"{label}.rs"
    path.write_text(source, encoding="utf-8")
    findings = rust_rules.scan_file(path)
    assert [f.rule_id for f in findings] == ["VGB-070"], label
    assert findings[0].severity == severity
    assert findings[0].line == 1


def test_rust_safe_idioms_are_not_reported(tmp_path):
    path = tmp_path / "safe.rs"
    path.write_text(
        'let c = std::process::Command::new("ls").arg("-l").output();\n'
        "let v = result.unwrap();\n",
        encoding="utf-8",
    )
    assert rust_rules.scan_file(path) == []


def test_rust_rule_ignores_non_rust_files(tmp_path):
    path = tmp_path / "main.go"
    path.write_text("unsafe { ptr.write(42) }\n", encoding="utf-8")
    assert rust_rules.scan_file(path) == []


def test_rust_rule_returns_no_findings_for_missing_file(tmp_path):
    assert rust_rules.scan_file(tmp_path / "gone.rs") == []


def test_rust_rule_ignores_commented_lines(tmp_path):
    path = tmp_path / "c.rs"
    path.write_text("// unsafe { ptr.write(42) }\n", encoding="utf-8")
    assert rust_rules.scan_file(path) == []


def test_rust_rule_ignores_calls_past_the_line_length_limit(tmp_path):
    limit = rust_rules.MAX_LINE_LENGTH
    source = "x" * (limit + 10) + "fn f() { unsafe { ptr.write(42) } }\n"
    target = tmp_path / "min.rs"
    target.write_text(source, encoding="utf-8")
    assert rust_rules.scan_file(target) == []


def test_rust_rule_truncates_long_snippet_in_output(tmp_path):
    line = "fn f() { unsafe { ptr.write(42) } }  // " + "y" * 200 + "\n"
    path = tmp_path / "long.rs"
    path.write_text(line, encoding="utf-8")
    finding = rust_rules.scan_file(path)[0]
    assert len(finding.snippet) == 123
    assert finding.snippet.endswith("...")


# ---------------------------------------------------------------------------
# VGB-080 — Java
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "source", "severity"),
    [
        ("deserialization", 'Object obj = new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject();\n', "CRITICAL"),
        ("command_injection", 'Runtime.getRuntime().exec("cmd " + userInput);\n', "CRITICAL"),
        ("sql_injection", 'stmt.executeQuery("SELECT * FROM t WHERE id = " + id);\n', "CRITICAL"),
    ],
)
def test_java_flags_each_pattern(tmp_path, label, source, severity):
    path = tmp_path / f"{label}.java"
    path.write_text(source, encoding="utf-8")
    findings = java_rules.scan_file(path)
    assert [f.rule_id for f in findings] == ["VGB-080"], label
    assert findings[0].severity == severity
    assert findings[0].line == 1


def test_java_safe_idioms_are_not_reported(tmp_path):
    """A parameterised query and a fixed argv are the safe idiom and must not fire."""
    path = tmp_path / "safe.java"
    path.write_text(
        "Object obj = mapper.readValue(bytes, Object.class);\n"
        'Runtime.getRuntime().exec(new String[]{"ls"});\n'
        'ps.executeQuery("SELECT * FROM t WHERE id = ?");\n',
        encoding="utf-8",
    )
    assert java_rules.scan_file(path) == []


def test_java_rule_ignores_non_java_files(tmp_path):
    path = tmp_path / "svc.js"
    path.write_text('Runtime.getRuntime().exec("cmd " + userInput);\n', encoding="utf-8")
    assert java_rules.scan_file(path) == []


def test_java_rule_returns_no_findings_for_missing_file(tmp_path):
    assert java_rules.scan_file(tmp_path / "gone.java") == []


def test_java_rule_ignores_commented_lines(tmp_path):
    path = tmp_path / "c.java"
    path.write_text('// Runtime.getRuntime().exec("cmd " + userInput);\n', encoding="utf-8")
    assert java_rules.scan_file(path) == []


def test_java_rule_ignores_calls_past_the_line_length_limit(tmp_path):
    limit = java_rules.MAX_LINE_LENGTH
    source = "x" * (limit + 10) + 'Runtime.getRuntime().exec("cmd " + userInput);\n'
    target = tmp_path / "min.java"
    target.write_text(source, encoding="utf-8")
    assert java_rules.scan_file(target) == []


def test_java_rule_truncates_long_snippet_in_output(tmp_path):
    line = 'Runtime.getRuntime().exec("cmd " + userInput);  // ' + "y" * 200 + "\n"
    path = tmp_path / "long.java"
    path.write_text(line, encoding="utf-8")
    finding = java_rules.scan_file(path)[0]
    assert len(finding.snippet) == 123
    assert finding.snippet.endswith("...")


# ---------------------------------------------------------------------------
# VGB-090 — Ruby
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "source", "severity"),
    [
        ("command_injection", 'system("rm -rf " + user_dir)\n', "CRITICAL"),
        ("eval_user_input", "eval(user_input)\n", "CRITICAL"),
        ("constantize_user_input", "klass = params[:model].to_s.constantize\n", "HIGH"),
    ],
)
def test_ruby_flags_each_pattern(tmp_path, label, source, severity):
    path = tmp_path / f"{label}.rb"
    path.write_text(source, encoding="utf-8")
    findings = ruby_rules.scan_file(path)
    assert [f.rule_id for f in findings] == ["VGB-090"], label
    assert findings[0].severity == severity
    assert findings[0].line == 1


def test_ruby_safe_idioms_are_not_reported(tmp_path):
    """A fixed argv, a literal, and a fixed constant are the safe idiom."""
    path = tmp_path / "safe.rb"
    path.write_text(
        "system(['rm', '-rf', dir])\n"
        "eval(1 + 1)\n"
        'klass = "Fixed".constantize\n',
        encoding="utf-8",
    )
    assert ruby_rules.scan_file(path) == []


def test_ruby_rule_ignores_non_ruby_files(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("eval(user_input)\n", encoding="utf-8")
    assert ruby_rules.scan_file(path) == []


def test_ruby_rule_returns_no_findings_for_missing_file(tmp_path):
    assert ruby_rules.scan_file(tmp_path / "gone.rb") == []


def test_ruby_rule_ignores_commented_lines(tmp_path):
    path = tmp_path / "c.rb"
    path.write_text("# system('rm -rf ' + user_dir)\n", encoding="utf-8")
    assert ruby_rules.scan_file(path) == []


def test_ruby_rule_ignores_calls_past_the_line_length_limit(tmp_path):
    limit = ruby_rules.MAX_LINE_LENGTH
    source = "x" * (limit + 10) + "eval(user_input)\n"
    target = tmp_path / "min.rb"
    target.write_text(source, encoding="utf-8")
    assert ruby_rules.scan_file(target) == []


def test_ruby_rule_truncates_long_snippet_in_output(tmp_path):
    line = "eval(user_input)  # " + "y" * 200 + "\n"
    path = tmp_path / "long.rb"
    path.write_text(line, encoding="utf-8")
    finding = ruby_rules.scan_file(path)[0]
    assert len(finding.snippet) == 123
    assert finding.snippet.endswith("...")

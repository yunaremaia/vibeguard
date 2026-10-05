"""Behavioural tests for VGB-050 (LLM output reaching a code-execution sink).

Every check gets a positive, a negative that must stay silent, and a location
assertion. The negatives are the interesting half: this rule is a name-and-shape
match, so the cases that decide whether it is usable are ordinary code with an
ordinary variable name, and model-free code that merely uses a sink.
"""

from pathlib import Path

from vibeguard.rules import llm_output
from vibeguard.rules.llm_output import RULE_ID
from vibeguard.scanner import scan_file as scan_all_rules


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def rule_ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# The canonical AI-generated-code case: the model writes the code, exec runs it
# ---------------------------------------------------------------------------


def test_exec_of_model_completion_is_flagged(tmp_path):
    source = 'exec(llm.complete(prompt))\n'
    findings = llm_output.scan_file(write(tmp_path, "app.py", source))
    assert rule_ids(findings) == [RULE_ID]
    assert findings[0].severity == "CRITICAL"
    assert findings[0].line == 1
    assert findings[0].column == 1
    assert "exec" in findings[0].message
    assert "attacker-influenced" in findings[0].message
    assert "literal_eval" in findings[0].fix_hint


def test_eval_of_choices_text_is_flagged(tmp_path):
    source = "result = eval(response.choices[0].text)\n"
    findings = llm_output.scan_file(write(tmp_path, "app.py", source))
    assert rule_ids(findings) == [RULE_ID]
    assert "eval" in findings[0].message
    assert findings[0].line == 1


def test_pickle_loads_of_model_output_is_flagged(tmp_path):
    source = "state = pickle.loads(completion_blob)\n"
    findings = llm_output.scan_file(write(tmp_path, "app.py", source))
    assert rule_ids(findings) == [RULE_ID]
    assert "pickle.loads" in findings[0].message


def test_shell_sink_reaching_the_model_is_flagged(tmp_path):
    source = "os.system(gpt_output)\n"
    findings = llm_output.scan_file(write(tmp_path, "app.py", source))
    assert rule_ids(findings) == [RULE_ID]
    assert "os.system" in findings[0].message


def test_every_registered_sink_is_flagged(tmp_path):
    """A sink added to SINK_RE without a case here fails the coverage gate loudly."""
    cases = {
        "eval(model_response)": "eval",
        "exec(llm_output)": "exec",
        "os.popen(agent_reply)": "os.popen",
        "subprocess.run(bot_command, shell=True)": "subprocess.run",
        "subprocess.Popen(llm_command, shell=True)": "subprocess.Popen",
        "obj = eval(model_code)": "eval",
        "cfg = yaml.load(llm_yaml)": "yaml.load",
    }
    for line, sink in cases.items():
        findings = llm_output.scan_file(write(tmp_path, "app.py", line + "\n"))
        assert rule_ids(findings) == [RULE_ID], line
        assert sink in findings[0].message, line


# ---------------------------------------------------------------------------
# Negatives: the sink is the constant, not the model. These decide whether the
# rule is usable at all.
# ---------------------------------------------------------------------------


def test_exec_of_a_plain_variable_is_silent(tmp_path):
    """The ordinary case. VGB-003 covers the request-fed variants; this must not."""
    assert llm_output.scan_file(write(tmp_path, "app.py", "exec(generated)\n")) == []


def test_eval_of_request_data_is_silent(tmp_path):
    """VGB-003's case, not VGB-050's — no double report on one line."""
    assert llm_output.scan_file(write(tmp_path, "app.py", "eval(request.body)\n")) == []


def test_sink_of_a_config_value_is_silent(tmp_path):
    source = "exec(config['startup_snippet'])\n"
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_model_named_but_handled_as_data_is_silent(tmp_path):
    """Parsed as data, not executed: the sanctioned fix, so it must stay quiet."""
    source = (
        "result = ast.literal_eval(llm_output)\n"
        "data = json.loads(model_response)\n"
        "state = yaml.safe_load(completion_blob)\n"
        "parsed = JSON.parse(gpt_output)\n"
    )
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_words_that_merely_start_like_a_model_token_are_silent(tmp_path):
    """``ai`` is a prefix of ordinary words; only ``ai_``/``ai.`` counts.

    This is the adversarial case for the bare-variable alternative: without the
    separator requirement these eight all report.
    """
    source = (
        "exec(aircraft_data)\n"
        "exec(aid_response)\n"
        "exec(aim_value)\n"
        "exec(llama_path)\n"
        "exec(chain_config)\n"
        "exec(main_handler)\n"
        "exec(chatbot_token)\n"
        "exec(details)\n"
    )
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_ai_prefixed_variable_with_separator_is_flagged(tmp_path):
    """The tightened rule still catches the name it was written for."""
    source = "exec(ai_output)\n"
    findings = llm_output.scan_file(write(tmp_path, "app.py", source))
    assert rule_ids(findings) == [RULE_ID]


def test_bare_model_word_without_a_qualifier_is_silent(tmp_path):
    """``exec(model)`` names no model output, so it is left to VGB-003's shape."""
    source = "exec(model)\n"
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_model_used_without_a_sink_is_silent(tmp_path):
    source = (
        "reply = client.chat.completions.create(model='gpt-4', messages=msgs)\n"
        "answer = reply.choices[0].message.content\n"
        "return jsonify({'answer': answer})\n"
    )
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_method_named_like_a_sink_is_silent(tmp_path):
    """``self.eval()`` and ``obj.exec()`` are methods, not the builtins."""
    source = (
        "self.eval(llm_output)\n"
        "sandbox.exec(agent_reply)\n"
        "plugin.eval(completion_blob)\n"
    )
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_sink_names_merely_appearing_in_a_string_are_silent(tmp_path):
    """A docstring that mentions exec/eval must not be read as a call."""
    source = 'description = "call exec() on the response, never eval(model_output)"\n'
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_sink_whose_argument_is_parsed_as_data_is_silent(tmp_path):
    """The guard is checked inside the sink's argument, not the whole line.

    ``eval(ast.literal_eval(llm_output))`` still names a sink, but its argument
    is parsed rather than executed, so it must not report.
    """
    source = "result = eval(ast.literal_eval(llm_output))\n"
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_apostrophe_inside_a_string_does_not_close_it_early(tmp_path):
    """The quote that opened the string is tracked, so "it's" stays one string."""
    source = "note = \"it's fine\"; exec(llm_output)\n"
    findings = llm_output.scan_file(write(tmp_path, "app.py", source))
    assert rule_ids(findings) == [RULE_ID]
    assert findings[0].line == 1


def test_real_call_after_a_string_on_the_same_line_is_flagged(tmp_path):
    """The guard is scoped to the quoted span, not to the whole line."""
    source = "log = 'starting'; exec(llm_output)\n"
    findings = llm_output.scan_file(write(tmp_path, "app.py", source))
    assert rule_ids(findings) == [RULE_ID]
    assert findings[0].column == 19


def test_comments_are_not_flagged(tmp_path):
    source = (
        "# exec(llm_output) was removed\n"
        "// eval(model_response)\n"
        "  * exec(gpt_output)\n"
    )
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_two_sinks_on_one_line_report_twice(tmp_path):
    source = "eval(llm_output); exec(model_response)\n"
    findings = llm_output.scan_file(write(tmp_path, "app.py", source))
    # Columns point at each sink: the eval at 1, the exec at 19.
    assert [(f.rule_id, f.column) for f in findings] == [(RULE_ID, 1), (RULE_ID, 19)]


# ---------------------------------------------------------------------------
# Shared behaviour
# ---------------------------------------------------------------------------


def test_hardened_llm_pipeline_is_clean(tmp_path):
    """One file where the model is used the safe way: the rule must stay silent."""
    source = (
        "prompt = build_prompt(request.json['message'])\n"
        "reply = client.chat.completions.create(model='gpt-4', messages=msgs)\n"
        "answer = reply.choices[0].message.content\n"
        "data = json.loads(llm_output)\n"
        "actions = ast.literal_eval(llm_output)\n"
        "state = yaml.safe_load(completion_blob)\n"
        "os.system(f'ls {directory}')\n"
        "eval(expression)\n"
    )
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_unreadable_file_yields_no_findings(tmp_path):
    assert llm_output.scan_file(tmp_path / "gone.py") == []


def test_long_line_snippet_is_truncated(tmp_path):
    source = "exec(llm_output)  # " + "x" * 400 + "\n"
    findings = llm_output.scan_file(write(tmp_path, "app.py", source))
    assert findings[0].snippet.endswith("...")
    assert len(findings[0].snippet) == 123


def test_oversized_line_is_truncated_before_matching(tmp_path):
    """A sink past the per-line cap is cut off, and the rule must not blow up.

    The sink sits *after* the cap on one long line, so truncation removes it:
    the finding that the same source produces on a short line is gone here.
    """
    tail = "exec(llm_output)"
    source = "x" * 60_000 + tail + "\n"
    assert llm_output.scan_file(write(tmp_path, "app.py", source)) == []


def test_sink_before_the_cap_on_a_long_line_still_reports(tmp_path):
    """Truncation must not swallow a sink that sits early in a long line."""
    source = "exec(llm_output)" + "  # " + "x" * 60_000 + "\n"
    findings = llm_output.scan_file(write(tmp_path, "app.py", source))
    assert rule_ids(findings) == [RULE_ID]


def test_malformed_source_does_not_raise(tmp_path):
    source = (
        "exec(\x00)\n"
        "eval('''\n"
        "os.system(\\\n"
        "exec(\n"
    )
    assert isinstance(llm_output.scan_file(write(tmp_path, "weird.py", source)), list)


def test_llm_output_rule_fires_through_the_scanner(tmp_path):
    findings = scan_all_rules(write(tmp_path, "app.py", "exec(llm.complete(prompt))\n"))
    assert rule_ids(findings).count(RULE_ID) == 1
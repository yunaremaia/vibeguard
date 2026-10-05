"""Model output trusted as code (VGB-050).

VGB-003 flags a dangerous function fed by *request* data — ``eval(req.body)``.
The gap is the second-order source: an LLM's own answer. The prompt reaching
the model is attacker-influenced, so ``exec(llm.complete(prompt))`` is remote
code execution with one request of setup, and nothing else in the registry
looks at that source. VGB-022 does not either — its input sources are HTTP
fields, argv and the environment, never a completion.

Scope is deliberately the pattern surface, like every other rule module: plain
stdlib ``re`` over lines, no parser, no cross-statement dataflow. The model
source is matched inside the sink's own argument text, so the report names the
place the fix goes.

# ponytail: single-line argument, no statement dataflow. A taint-tracking pass
# (LLM result bound on line 3, exec'd on line 40) is the upgrade if this misses
# a real one; the sinks are all here, so a `model_output`-named variable
# reaching them later is the case that needs it.
"""

import logging
import re
from pathlib import Path

from ..models import Finding, Severity

logger = logging.getLogger(__name__)

RULE_ID = "VGB-050"

MAX_LINE_LENGTH = 50_000  # 50 KB, same cap as the other line scanners

# Code-execution sinks. ``(?<![\w.])`` keeps ``myobj.eval(`` and ``self.exec(``
# out: a method with a familiar name is not the builtin. ``shell=True`` and the
# picklers are included because they execute model output just as directly.
SINK_RE = re.compile(
    r"""(?<![\w.]) (?P<sink>
        eval | exec
      | os \s* \. \s* (?: system | popen )
      | subprocess \s* \. \s* (?: run | call | check_call | check_output | Popen )
      | new \s+ Function
      | pickle \s* \. \s* loads?
      | yaml \s* \. \s* load
    ) \s* \( """,
    re.IGNORECASE | re.VERBOSE,
)

# The model source, matched in the sink's argument. Any one alternative is
# enough, in decreasing order of how LLM-shaped it is:
#   1. a model-ish receiver reaching a completion attribute
#      (``completion.choices[0].text``, ``response.content``, ``llm.output``)
#   2. the SDK's own chained accessors (``res.choices``, ``output_text``,
#      ``.generate_content(``, ``ChatCompletion.create``) - unambiguous shapes
#   3. a bare variable named after a model (``llm_output``, ``gpt_response``)
# A plain name like ``answer`` or ``reply`` is deliberately NOT enough: those
# are ordinary variables in code with no model in it, and VGB-050 claims a
# cause it cannot see. Alternative 3 requires a separator after the model
# word, so ``aircraft_data`` and ``agent_id`` - ordinary words that merely
# start like a model token - stay silent.
MODEL_OUTPUT_RE = re.compile(
    r"""(?ix)
      \w* (?: llm | model | gpt | openai | anthropic | gemini | claude
          | generation | completion | chat | agent | bot )
      \w* \s* \. \s* (?: choices | candidates | content | text | message
                        | output_text | generated_text | output )
    | (?: \. \s* (?: choices | candidates | output_text | generated_text ) )
    | \b (?: openai | anthropic | gemini | claude | ChatCompletion
          | completions | generate_content | messages )
      \s* \. \s* create
    | \. \s* generate_content \s* \(
    | (?: ^ | [\s(=,]) \s*
      \b (?: llm | model | gpt | openai | anthropic | gemini | claude
          | generation | completion | chat | agent | bot )
      (?: _ | \- | \. ) [\w]+ \b
    | (?: ^ | [\s(=,]) \s*
      \b ai (?: _ | \- | \. ) [\w]+ \b
    """
)

# Parsing the value as data instead of executing it. These make the sink safe,
# so they suppress the finding rather than decorating it.
LITERAL_PARSER_RE = re.compile(
    r"""(?ix) \b (?: ast \. literal_eval | literal_eval | json \. loads?
                  | yaml \. safe_load | safe_load | JSON \. parse
                  | parse_json ) \b """
)


def _snippet(line: str) -> str:
    text = line.strip()
    return text if len(text) <= 120 else text[:120] + "..."


def _inside_string(line: str, index: int) -> bool:
    """True when ``index`` falls inside a quoted string on this line.

    A docstring or a message that *names* a sink ("call exec() first") must not
    read as a call. The quote that opened the string is tracked, so the
    apostrophe in ``"it's"`` does not close it early.

    # ponytail: single-line scan, no tokenizer. A line whose quotes do not
    # balance hides the rest of the line; a real tokenizer if that shows up.
    """
    quote = ""
    for char in line[:index]:
        if not quote:
            if char in "\"'":
                quote = char
        elif char == quote:
            quote = ""
    return bool(quote)


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for LLM output reaching a code-execution sink."""
    findings: list[Finding] = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*")):
            continue

        if len(line) > MAX_LINE_LENGTH:
            line = line[:MAX_LINE_LENGTH]

        for match in SINK_RE.finditer(line):
            if _inside_string(line, match.start()):
                continue
            argument = line[match.end() :]
            if LITERAL_PARSER_RE.search(argument):
                continue

            source = MODEL_OUTPUT_RE.search(argument)
            if not source:
                continue

            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    severity=Severity.CRITICAL,
                    message=(
                        f"{match.group('sink')}() executes LLM output "
                        f"({source.group(0).strip()}) — model output is attacker-influenced"
                    ),
                    file=str(path),
                    line=line_num,
                    column=match.start() + 1,
                    snippet=_snippet(line),
                    fix_hint=(
                        "Never execute model output. Parse it as data "
                        "(ast.literal_eval, json.loads) and allowlist the operations it may name"
                    ),
                )
            )

    return findings
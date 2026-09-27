"""Simple command-line interface for one-off input/output scans."""

import argparse
import json
import sys

from .guard import Guard


def main() -> None:
    parser = argparse.ArgumentParser(prog="llm-guard", description="Scan LLM text locally for common risks.")
    parser.add_argument("direction", choices=("input", "output"), help="Text direction across your model boundary")
    parser.add_argument("text", nargs="?", help="Text to scan; omit to read stdin")
    parser.add_argument("--json", action="store_true", help="Print the structured result as JSON")
    parser.add_argument("--redact", action="store_true", help="Print a redacted copy of flagged text")
    args = parser.parse_args()
    text = args.text if args.text is not None else sys.stdin.read()
    guard = Guard()
    result = guard.check_input(text) if args.direction == "input" else guard.check_output(text)
    payload = result.to_dict()
    if args.redact and args.direction == "output":
        payload["redacted_text"] = guard.redact(text, result)
    print(json.dumps(payload, indent=2) if args.json else f"{result.verdict.value.upper()} ({result.risk_score:.2f})\n" + "\n".join(f"- {reason}" for reason in result.reasons))
    raise SystemExit(1 if result.is_blocked else 0)

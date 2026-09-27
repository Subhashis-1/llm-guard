"""Small precision-oriented rule sets; matches are reported, never executed."""

import re
from collections.abc import Iterable

from .models import Detection, Severity

_INPUT_PATTERNS: tuple[tuple[str, str, Severity, re.Pattern[str]], ...] = (
    ("override_instructions", "LLM01", Severity.HIGH, re.compile(r"\b(?:ignore|disregard|override|forget)\b.{0,60}\b(?:previous|prior|above|system|developer|all)\b.{0,30}\b(?:instructions?|rules?|prompt)\b", re.I)),
    ("reveal_prompt", "LLM07", Severity.HIGH, re.compile(r"\b(?:reveal|print|show|repeat|expose|leak)\b.{0,50}\b(?:system|hidden|developer)\s+(?:prompt|instructions?)\b", re.I)),
    ("role_override", "LLM01", Severity.MEDIUM, re.compile(r"\b(?:you are now|act as|pretend to be)\s+(?:dan|an? unrestricted|a different|developer|system)\b", re.I)),
    ("guardrail_bypass", "LLM01", Severity.MEDIUM, re.compile(r"\b(?:bypass|disable|circumvent|remove)\b.{0,35}\b(?:safety|guardrails?|restrictions?|filters?)\b", re.I)),
)

_OUTPUT_PATTERNS: tuple[tuple[str, str, Severity, re.Pattern[str], str], ...] = (
    ("openai_key", "LLM02", Severity.CRITICAL, re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "OpenAI-style API key"),
    ("anthropic_key", "LLM02", Severity.CRITICAL, re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "Anthropic-style API key"),
    ("aws_key", "LLM02", Severity.CRITICAL, re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "AWS access key"),
    ("github_token", "LLM02", Severity.CRITICAL, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "GitHub token"),
    ("private_key", "LLM02", Severity.CRITICAL, re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private key header"),
    ("email", "LLM02", Severity.MEDIUM, re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "Email address"),
    ("us_ssn", "LLM02", Severity.HIGH, re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), "US Social Security number pattern"),
    ("payment_card", "LLM02", Severity.HIGH, re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "Payment-card-like number"),
)


def _detection(rule_id: str, category: str, severity: Severity, message: str, match: re.Match[str]) -> Detection:
    # Do not expose matched secrets in normal reports; offsets are enough for redaction.
    return Detection(rule_id, category, severity, message, match.start(), match.end())


def scan_input(text: str, normalized: str) -> list[Detection]:
    detections: list[Detection] = []
    for rule_id, category, severity, pattern in _INPUT_PATTERNS:
        for match in pattern.finditer(normalized):
            detections.append(_detection(rule_id, category, severity, "Possible prompt override or exfiltration request.", match))
    return detections


def scan_output(text: str) -> list[Detection]:
    detections: list[Detection] = []
    for rule_id, category, severity, pattern, label in _OUTPUT_PATTERNS:
        for match in pattern.finditer(text):
            detections.append(_detection(rule_id, category, severity, f"Possible {label} detected.", match))
    return detections


def merge_detections(groups: Iterable[Iterable[Detection]]) -> tuple[Detection, ...]:
    return tuple(d for group in groups for d in group)

"""Verdict aggregation with a critical-finding override."""

from collections.abc import Iterable

from .models import Detection, ScanResult, Severity, Verdict

_WEIGHTS = {Severity.LOW: 0.15, Severity.MEDIUM: 0.4, Severity.HIGH: 0.75, Severity.CRITICAL: 1.0}


def build_result(text: str, detections: Iterable[Detection], *, block_threshold: float = 0.7, flag_threshold: float = 0.3) -> ScanResult:
    findings = tuple(detections)
    # Noisy-OR aggregation avoids scores growing linearly with duplicate or overlapping rules.
    remaining = 1.0
    for detection in findings:
        remaining *= 1.0 - _WEIGHTS[detection.severity]
    score = 1.0 - remaining
    if any(d.severity is Severity.CRITICAL for d in findings) or score >= block_threshold:
        verdict = Verdict.BLOCK
    elif score >= flag_threshold:
        verdict = Verdict.FLAG
    else:
        verdict = Verdict.ALLOW
    return ScanResult(verdict, score, findings, text)

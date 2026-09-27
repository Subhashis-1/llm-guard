"""Public guard facade for adding checks at an LLM application's text boundary."""

from . import rules
from .models import ScanResult
from .normalize import normalize
from .scanner import build_result


class Guard:
    """Scan untrusted prompts and model responses without sending data to a service."""

    def __init__(self, *, block_threshold: float = 0.7, flag_threshold: float = 0.3) -> None:
        if not 0 <= flag_threshold <= block_threshold <= 1:
            raise ValueError("Thresholds must satisfy 0 <= flag_threshold <= block_threshold <= 1")
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold

    def check_input(self, text: str) -> ScanResult:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        detections = rules.scan_input(text, normalize(text))
        return build_result(text, detections, block_threshold=self.block_threshold, flag_threshold=self.flag_threshold)

    def check_output(self, text: str) -> ScanResult:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        detections = rules.scan_output(text)
        return build_result(text, detections, block_threshold=self.block_threshold, flag_threshold=self.flag_threshold)

    @staticmethod
    def redact(text: str, result: ScanResult, replacement: str = "[REDACTED]") -> str:
        """Redact output findings using right-to-left offsets so earlier spans remain valid."""
        spans = sorted(
            ((d.start, d.end) for d in result.detections if d.start is not None and d.end is not None),
            reverse=True,
        )
        for start, end in spans:
            text = text[:start] + replacement + text[end:]
        return text

"""Shared, JSON-friendly result types used by scanners and adapters."""

from dataclasses import asdict, dataclass
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Detection:
    rule_id: str
    category: str
    severity: Severity
    message: str
    start: int | None = None
    end: int | None = None
    matched_text: str | None = None

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True, slots=True)
class ScanResult:
    verdict: Verdict
    risk_score: float
    detections: tuple[Detection, ...]
    scanned_text: str

    @property
    def is_blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(d.message for d in self.detections))

    def to_dict(self, *, include_text: bool = False) -> dict[str, object]:
        result: dict[str, object] = {
            "verdict": self.verdict.value,
            "risk_score": round(self.risk_score, 4),
            "detections": [d.to_dict() for d in self.detections],
            "reasons": list(self.reasons),
        }
        if include_text:
            result["scanned_text"] = self.scanned_text
        return result

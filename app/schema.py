"""ECS-lite event schema + alert model.

Deliberately a *subset* of Elastic Common Schema so the contract is small enough
to defend in a viva, but still recognisable as real-world normalisation.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

# Fields the detector is allowed to see. Anything else (notably `label` /
# `technique` from the lab corpus) is ground truth and MUST NOT reach detection.
DATA_FIELDS = (
    "host", "user", "event_type", "process", "cmdline", "src_ip",
    "dst_ip", "path", "status", "user_agent", "message", "bytes",
)


def utcnow() -> datetime:
    return datetime.now(UTC)


class Event(BaseModel):
    """A single normalised telemetry record."""

    ts: datetime = Field(default_factory=utcnow)
    host: str = "unknown"
    user: Optional[str] = None
    event_type: str = "process"          # auth | process | file | network | http
    process: Optional[str] = None
    cmdline: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    path: Optional[str] = None
    status: Optional[str] = None         # success | failure
    user_agent: Optional[str] = None
    message: Optional[str] = None
    bytes: Optional[int] = None

    @field_validator("ts", mode="before")
    @classmethod
    def _parse_ts(cls, v: Any) -> Any:
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v, tz=UTC)
        if isinstance(v, str):
            s = v.replace("Z", "+00:00")
            return datetime.fromisoformat(s)
        return v

    @field_validator("host", "event_type", mode="before")
    @classmethod
    def _not_none(cls, v: Any) -> Any:
        return v if v not in (None, "") else ("unknown" if v is None else v)

    @classmethod
    def from_raw(cls, raw: dict) -> Event:
        """Normalise an arbitrary dict, dropping ground-truth fields."""
        clean = {k: v for k, v in raw.items() if k in DATA_FIELDS or k == "ts"}
        if "cmdline" in clean and isinstance(clean["cmdline"], list):
            clean["cmdline"] = " ".join(str(p) for p in clean["cmdline"])
        return cls(**clean)

    def searchable(self) -> str:
        """Concatenated attacker-influenced text — this is the *untrusted* input."""
        parts = [self.user, self.process, self.cmdline, self.path,
                 self.user_agent, self.message, self.src_ip]
        return " ".join(p for p in parts if p)


class Alert(BaseModel):
    id: str
    ts: datetime
    fingerprint: str
    rule_id: str
    title: str
    severity: str                        # low | medium | high | critical
    technique: Optional[str] = None      # ATT&CK ID from the rule
    why: str = ""                        # detection rationale shown to the analyst
    score: float = 0.0                   # fused confidence 0..1
    sources: list[str] = Field(default_factory=list)   # rule / anomaly
    event: Event
    triage: Optional[dict] = None
    status: str = "open"                 # open | blocked | closed
    created_at: datetime = Field(default_factory=utcnow)


class TriageResult(BaseModel):
    """Strict contract for the LLM. Anything else is rejected (defence D3)."""

    verdict: str            # true_positive | false_positive | needs_review
    severity: str           # low | medium | high | critical
    technique_id: str
    confidence: float
    narrative: str
    recommended_action: str

    @field_validator("verdict")
    @classmethod
    def _verdict(cls, v: str) -> str:
        allowed = {"true_positive", "false_positive", "needs_review"}
        if v not in allowed:
            raise ValueError(f"verdict must be one of {sorted(allowed)}")
        return v

    @field_validator("severity")
    @classmethod
    def _sev(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return v

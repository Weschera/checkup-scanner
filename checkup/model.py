"""Findings and grading."""
from __future__ import annotations

from dataclasses import asdict, dataclass

EMAIL = "Email spoofing"
WEB = "Website security"
SOFTWARE = "Software and exposure"
AI = "AI and chatbots"
AREAS = [EMAIL, WEB, SOFTWARE, AI]

ORDER = {"info": 0, "pass": 1, "warn": 2, "fail": 3}
GRADE = {0: "grey", 1: "green", 2: "yellow", 3: "red"}


@dataclass
class Finding:
    area: str
    status: str  # pass | warn | fail | info
    title: str
    detail: str = ""
    fix: str = ""

    def __post_init__(self) -> None:
        if self.status not in ORDER:
            raise ValueError(f"bad status {self.status!r}")
        if self.area not in AREAS:
            raise ValueError(f"bad area {self.area!r}")

    def to_dict(self) -> dict:
        return asdict(self)


def area_grade(findings: list[Finding], area: str) -> str:
    """Worst status in the area: red, yellow, green, or grey when only info."""
    levels = [ORDER[f.status] for f in findings if f.area == area]
    return GRADE[max(levels)] if levels else "grey"

"""Regulatory notification clocks (indicative; confirm against the law that applies to you).

Each step's deadline is computed from the incident's ``aware_at`` (when the organisation became
aware), never stored, so correcting ``aware_at`` moves every deadline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class Step:
    key: str
    label: str
    after: timedelta
    note: str = ""


@dataclass(frozen=True)
class Regime:
    key: str
    label: str
    authority: str
    steps: tuple[Step, ...]
    personal_data: bool = False  # suggested when personal data is affected


REGIMES: dict[str, Regime] = {
    r.key: r
    for r in (
        Regime(
            "gdpr",
            "GDPR personal data breach",
            "Lead supervisory authority",
            (
                Step(
                    "authority",
                    "Notify the supervisory authority (Art. 33)",
                    timedelta(hours=72),
                    "Unless the breach is unlikely to result in a risk to individuals.",
                ),
            ),
            personal_data=True,
        ),
        Regime(
            "dpdp",
            "India DPDP Act personal data breach",
            "Data Protection Board of India (and affected Data Principals)",
            (
                Step(
                    "intimation",
                    "Intimate the Board without delay",
                    timedelta(hours=24),
                    "No fixed hour limit in the Act; 24 h is used here as 'without delay'.",
                ),
                Step("report", "Detailed report to the Board (DPDP Rules)", timedelta(hours=72)),
            ),
            personal_data=True,
        ),
        Regime(
            "nis2",
            "NIS2 significant incident",
            "National CSIRT / competent authority",
            (
                Step("early_warning", "Early warning", timedelta(hours=24)),
                Step("notification", "Incident notification", timedelta(hours=72)),
                Step(
                    "final",
                    "Final report",
                    timedelta(days=30),
                    "One month after the incident notification; measured here from awareness.",
                ),
            ),
        ),
        Regime(
            "dora",
            "DORA major ICT-related incident",
            "Competent financial authority",
            (
                Step(
                    "initial",
                    "Initial notification",
                    timedelta(hours=24),
                    "4 h after classification as major, at most 24 h after awareness.",
                ),
                Step(
                    "intermediate",
                    "Intermediate report",
                    timedelta(hours=96),
                    "72 h after the initial notification; measured here from awareness.",
                ),
                Step("final", "Final report", timedelta(days=30)),
            ),
        ),
        Regime(
            "certin",
            "CERT-In cyber incident (India)",
            "CERT-In",
            (Step("report", "Report to CERT-In", timedelta(hours=6)),),
        ),
    )
}
REGIME_CHOICES = [(r.key, r.label) for r in REGIMES.values()]

"""Point-in-time snapshots used ONLY for trend charts.

Current state is always computed live; these rows answer "what did it look like on date X".
One row per organisation/date (/framework), written by the daily job (idempotent).
"""

from __future__ import annotations

from django.db import models

from threatledger.frameworks.models import Framework
from threatledger.org.models import Organisation


class ComplianceSnapshot(models.Model):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    framework = models.ForeignKey(Framework, on_delete=models.CASCADE, related_name="snapshots")
    date = models.DateField(db_index=True)
    met = models.PositiveIntegerField()
    partial = models.PositiveIntegerField()
    gap = models.PositiveIntegerField()
    no_control = models.PositiveIntegerField()
    tracked = models.PositiveIntegerField()
    percent = models.FloatField()

    class Meta:
        ordering = ["date"]
        constraints = [
            models.UniqueConstraint(
                fields=["organisation", "framework", "date"], name="uniq_compliance_snapshot"
            )
        ]

    def __str__(self) -> str:
        return f"{self.framework.code} {self.date}: {self.percent}%"


class CoverageSnapshot(models.Model):
    """Threat coverage of the techniques in the risk register."""

    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    date = models.DateField(db_index=True)
    covered = models.PositiveIntegerField()
    partial = models.PositiveIntegerField()
    gap = models.PositiveIntegerField()
    percent = models.FloatField()

    class Meta:
        ordering = ["date"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "date"], name="uniq_coverage_snapshot")
        ]

    def __str__(self) -> str:
        return f"coverage {self.date}: {self.percent}%"


class RiskSnapshot(models.Model):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    date = models.DateField(db_index=True)
    open_risks = models.PositiveIntegerField()
    residual = models.JSONField(default=dict)  # {"low": n, "medium": n, "high": n, "critical": n}
    inherent = models.JSONField(default=dict)
    average_residual = models.FloatField(default=0)

    class Meta:
        ordering = ["date"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "date"], name="uniq_risk_snapshot")
        ]

    def __str__(self) -> str:
        return f"risks {self.date}: {self.open_risks} open"

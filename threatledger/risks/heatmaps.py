"""Heatmap grid helpers shared by the heatmap page, dashboard and board report."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Any

from .models import Band, RiskMatrix


def grid(matrix: RiskMatrix, counts: Counter[tuple[int, int]]) -> list[dict[str, Any]]:
    """Rows from highest likelihood down; each row has one cell per impact value."""
    rows = []
    for likelihood in reversed(matrix.scale):
        cells = []
        for impact in matrix.scale:
            score = likelihood * impact
            cells.append(
                {
                    "likelihood": likelihood,
                    "impact": impact,
                    "score": score,
                    "band": matrix.band(score),
                    "count": counts.get((likelihood, impact), 0),
                }
            )
        rows.append(
            {"likelihood": likelihood, "label": matrix.likelihood_label(likelihood), "cells": cells}
        )
    return rows


def band_counts(matrix: RiskMatrix, values: Sequence[tuple[int, ...]]) -> list[dict[str, Any]]:
    out = []
    for band in Band:
        out.append(
            {
                "band": band,
                "inherent": sum(1 for v in values if matrix.band(v[0] * v[1]) == band),
                "residual": sum(1 for v in values if matrix.band(v[2] * v[3]) == band),
            }
        )
    return out

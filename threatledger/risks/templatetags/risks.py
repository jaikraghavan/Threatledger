from __future__ import annotations

from typing import Any

from django import template

register = template.Library()


@register.filter
def band(score: int, matrix: Any) -> str:
    """``{{ risk.residual.value|band:matrix }}`` -> "high" (use for CSS classes)."""
    return str(matrix.band(int(score)).value)


@register.filter
def band_label(score: int, matrix: Any) -> str:
    return str(matrix.band(int(score)).label)

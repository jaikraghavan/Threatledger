from __future__ import annotations

import calendar
from datetime import date


def add_months(d: date, months: int) -> date:
    """``d`` plus ``months`` calendar months, clamped to the end of shorter months."""
    month = d.month - 1 + months
    year, month = d.year + month // 12, month % 12 + 1
    return date(year, month, min(d.day, calendar.monthrange(year, month)[1]))

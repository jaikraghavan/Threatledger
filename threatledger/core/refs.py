"""Human-readable sequential references (A-0001, F-0001, …) per organisation."""

from __future__ import annotations

import re
from typing import Any

from threatledger.org.models import Organisation


def next_ref(model: Any, org: Organisation, prefix: str, width: int = 4) -> str:
    """Next ``<prefix>-nnnn`` for ``model`` in ``org``.

    Locks the organisation row so concurrent creates don't clash; call inside a transaction.
    """
    Organisation.objects.select_for_update().filter(pk=org.pk).first()
    pattern = re.compile(rf"^{re.escape(prefix)}-(\d+)$")
    highest = 0
    for ref in model.objects.filter(organisation=org).values_list("ref", flat=True):
        m = pattern.match(ref)
        if m:
            highest = max(highest, int(m.group(1)))
    return f"{prefix}-{highest + 1:0{width}d}"

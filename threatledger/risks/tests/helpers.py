"""Shared builders for Phase 3 tests."""

from __future__ import annotations

from typing import Any

from threatledger.attack.models import Mitigation, MitigationTechnique, Technique
from threatledger.controls.models import Control, ControlMitigation, ControlTechnique
from threatledger.org.models import Organisation
from threatledger.risks import services
from threatledger.risks.models import Risk

BASE_SCORES = {
    "inherent_likelihood": 4,
    "inherent_impact": 5,
    "residual_likelihood": 2,
    "residual_impact": 4,
}


def make_risk(user: Any, **overrides: Any) -> Risk:
    data = {
        "title": "Ransomware via phishing",
        "scenario": "Phish → macro → encryption.",
        **BASE_SCORES,
    }
    assets = overrides.pop("assets", ())
    data.update(overrides)
    return services.create_risk(user=user, data=data, assets=assets)


def make_control(org: Organisation, ref: str, status: str = "implemented", **kw: Any) -> Control:
    return Control.objects.create(
        organisation=org, ref=ref, name=kw.pop("name", ref), status=status, **kw
    )


def technique(
    attack_id: str, name: str | None = None, parent: Technique | None = None, **kw: Any
) -> Technique:
    return Technique.objects.create(
        stix_id=f"attack-pattern--{attack_id}",
        attack_id=attack_id,
        name=name or attack_id,
        parent=parent,
        is_subtechnique=parent is not None,
        **kw,
    )


def mitigation(attack_id: str, *techniques: Technique) -> Mitigation:
    m = Mitigation.objects.create(
        stix_id=f"course-of-action--{attack_id}", attack_id=attack_id, name=attack_id
    )
    for t in techniques:
        MitigationTechnique.objects.create(mitigation=m, technique=t)
    return m


def map_direct(control: Control, *techniques: Technique) -> None:
    for t in techniques:
        ControlTechnique.objects.create(control=control, technique=t)


def map_mitigation(control: Control, m: Mitigation) -> None:
    ControlMitigation.objects.create(control=control, mitigation=m)

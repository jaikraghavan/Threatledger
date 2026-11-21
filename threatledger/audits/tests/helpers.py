from __future__ import annotations

from threatledger.frameworks.importer import load, parse
from threatledger.frameworks.models import Framework, Requirement

FW = b"""
framework: {code: FW-A, name: Framework A, baselines: [low, moderate]}
requirements:
  - {ref: D, title: Domain, is_domain: true}
  - {ref: A-1, title: One, parent: D, baselines: [low, moderate]}
  - {ref: A-2, title: Two, parent: D, baselines: [moderate]}
  - {ref: A-3, title: Three, parent: D, baselines: [moderate]}
"""


def framework() -> Framework:
    return load(parse(FW, "a.yaml")).framework


def req(fw: Framework, ref: str) -> Requirement:
    return Requirement.objects.get(framework=fw, ref=ref)

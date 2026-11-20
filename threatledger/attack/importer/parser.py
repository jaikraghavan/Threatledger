"""Parse an ATT&CK STIX 2.1 bundle into plain records. Pure: no database access.

Handles both detection models:
- v18+: ``x-mitre-detection-strategy --detects--> attack-pattern``, strategies reference
  analytics, analytics reference data components via ``x_mitre_log_source_references``;
- older: ``x-mitre-data-component --detects--> attack-pattern`` and data sources.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

MITRE_SOURCE = "mitre-attack"
KILL_CHAIN = "mitre-attack"


class BundleError(ValueError):
    """The input is not a usable ATT&CK bundle."""


Record = dict[str, Any]
Link = tuple[str, str, str]  # (source stix id, target stix id, description)


@dataclass
class ParsedBundle:
    domain: str
    version: str
    spec_version: str
    tactics: list[Record] = field(default_factory=list)
    techniques: list[Record] = field(default_factory=list)
    groups: list[Record] = field(default_factory=list)
    software: list[Record] = field(default_factory=list)
    mitigations: list[Record] = field(default_factory=list)
    data_sources: list[Record] = field(default_factory=list)
    data_components: list[Record] = field(default_factory=list)
    detection_strategies: list[Record] = field(default_factory=list)
    analytics: list[Record] = field(default_factory=list)
    technique_tactics: dict[str, list[str]] = field(default_factory=dict)  # stix -> shortnames
    subtechnique_of: dict[str, str] = field(default_factory=dict)  # child stix -> parent stix
    revoked_by: dict[str, str] = field(default_factory=dict)  # old stix -> new stix
    data_component_source: dict[str, str] = field(default_factory=dict)  # dc stix -> ds stix
    analytic_strategies: dict[str, list[str]] = field(default_factory=dict)
    analytic_components: dict[str, list[str]] = field(default_factory=dict)
    links: dict[str, list[Link]] = field(default_factory=lambda: defaultdict(list))


# (relationship_type, source type(s), target type(s)) -> link table name
_LINK_RULES: list[tuple[str, frozenset[str], frozenset[str], str]] = [
    ("uses", frozenset({"intrusion-set"}), frozenset({"attack-pattern"}), "group_technique"),
    (
        "uses",
        frozenset({"malware", "tool"}),
        frozenset({"attack-pattern"}),
        "software_technique",
    ),
    ("uses", frozenset({"intrusion-set"}), frozenset({"malware", "tool"}), "group_software"),
    (
        "mitigates",
        frozenset({"course-of-action"}),
        frozenset({"attack-pattern"}),
        "mitigation_technique",
    ),
    (
        "detects",
        frozenset({"x-mitre-detection-strategy"}),
        frozenset({"attack-pattern"}),
        "detection_technique",
    ),
    (
        "detects",
        frozenset({"x-mitre-data-component"}),
        frozenset({"attack-pattern"}),
        "data_component_technique",
    ),
]


def _type_of(stix_id: str) -> str:
    return stix_id.split("--", 1)[0]


def _mitre_ref(obj: dict[str, Any]) -> dict[str, Any]:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == MITRE_SOURCE:
            return ref
    return {}


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if isinstance(v, str | int | float)]


def _base(obj: dict[str, Any]) -> Record:
    ref = _mitre_ref(obj)
    return {
        "stix_id": obj["id"],
        "attack_id": str(ref.get("external_id", ""))[:20],
        "name": str(obj.get("name", ""))[:300],
        "description": str(obj.get("description", "")),
        "url": str(ref.get("url", ""))[:300],
        "stix_modified": _dt(obj.get("modified")),
        "attack_version": str(obj.get("x_mitre_version", ""))[:16],
        "is_deprecated": bool(obj.get("x_mitre_deprecated", False)),
        "is_revoked": bool(obj.get("revoked", False)),
    }


def _in_domain(obj: dict[str, Any], domain: str) -> bool:
    domains = obj.get("x_mitre_domains")
    return not domains or domain in domains


def parse_bundle(bundle: Any, domain: str = "enterprise-attack") -> ParsedBundle:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise BundleError("not a STIX bundle (missing type=bundle)")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise BundleError("bundle has no objects")
    objects = [o for o in objects if isinstance(o, dict) and "id" in o and "type" in o]

    collection = next((o for o in objects if o["type"] == "x-mitre-collection"), None)
    if collection is None or not collection.get("x_mitre_version"):
        raise BundleError("bundle has no x-mitre-collection with x_mitre_version")
    matrices = [
        o for o in objects if o["type"] == "x-mitre-matrix" and not o.get("x_mitre_deprecated")
    ]
    if not matrices:
        raise BundleError("bundle has no x-mitre-matrix (needed for tactic order)")

    parsed = ParsedBundle(
        domain=domain,
        version=str(collection["x_mitre_version"])[:16],
        spec_version=str(collection.get("x_mitre_attack_spec_version", ""))[:16],
    )

    tactic_order: dict[str, int] = {}
    for ref in matrices[0].get("tactic_refs") or []:
        tactic_order.setdefault(ref, len(tactic_order))

    for obj in objects:
        kind = obj["type"]
        if not _in_domain(obj, domain):
            continue
        if kind == "x-mitre-tactic":
            rec = _base(obj)
            rec["shortname"] = str(obj.get("x_mitre_shortname", ""))[:64]
            rec["order"] = tactic_order.get(obj["id"])
            parsed.tactics.append(rec)
        elif kind == "attack-pattern":
            rec = _base(obj)
            rec["is_subtechnique"] = bool(obj.get("x_mitre_is_subtechnique", False))
            rec["platforms"] = _str_list(obj.get("x_mitre_platforms"))
            parsed.techniques.append(rec)
            parsed.technique_tactics[obj["id"]] = [
                p["phase_name"]
                for p in obj.get("kill_chain_phases") or []
                if p.get("kill_chain_name") == KILL_CHAIN and p.get("phase_name")
            ]
        elif kind == "intrusion-set":
            rec = _base(obj)
            aliases = [a for a in _str_list(obj.get("aliases")) if a != rec["name"]]
            rec["aliases"] = aliases
            rec["aliases_text"] = " | ".join(aliases)
            rec["revoked_by_stix_id"] = ""
            parsed.groups.append(rec)
        elif kind in ("malware", "tool"):
            rec = _base(obj)
            rec["kind"] = kind
            rec["aliases"] = [a for a in _str_list(obj.get("x_mitre_aliases")) if a != rec["name"]]
            rec["platforms"] = _str_list(obj.get("x_mitre_platforms"))
            rec["revoked_by_stix_id"] = ""
            parsed.software.append(rec)
        elif kind == "course-of-action":
            parsed.mitigations.append(_base(obj))
        elif kind == "x-mitre-data-source":
            parsed.data_sources.append(_base(obj))
        elif kind == "x-mitre-data-component":
            rec = _base(obj)
            rec["log_sources"] = [
                {"name": str(s.get("name", "")), "channel": str(s.get("channel", ""))}
                for s in obj.get("x_mitre_log_sources") or []
                if isinstance(s, dict)
            ]
            parsed.data_components.append(rec)
            if obj.get("x_mitre_data_source_ref"):
                parsed.data_component_source[obj["id"]] = obj["x_mitre_data_source_ref"]
        elif kind == "x-mitre-detection-strategy":
            parsed.detection_strategies.append(_base(obj))
            for analytic_ref in obj.get("x_mitre_analytic_refs") or []:
                parsed.analytic_strategies.setdefault(analytic_ref, []).append(obj["id"])
        elif kind == "x-mitre-analytic":
            rec = _base(obj)
            rec["platforms"] = _str_list(obj.get("x_mitre_platforms"))
            parsed.analytics.append(rec)
            parsed.analytic_components[obj["id"]] = sorted(
                {
                    s["x_mitre_data_component_ref"]
                    for s in obj.get("x_mitre_log_source_references") or []
                    if isinstance(s, dict) and s.get("x_mitre_data_component_ref")
                }
            )

    for rel in objects:
        if rel["type"] != "relationship" or rel.get("revoked") or rel.get("x_mitre_deprecated"):
            continue
        rtype, src, tgt = rel.get("relationship_type"), rel.get("source_ref"), rel.get("target_ref")
        if not (isinstance(src, str) and isinstance(tgt, str)):
            continue
        if rtype == "subtechnique-of":
            parsed.subtechnique_of[src] = tgt
            continue
        if rtype == "revoked-by":
            parsed.revoked_by[src] = tgt
            continue
        src_type, tgt_type = _type_of(src), _type_of(tgt)
        for rule_type, src_types, tgt_types, table in _LINK_RULES:
            if rtype == rule_type and src_type in src_types and tgt_type in tgt_types:
                parsed.links[table].append((src, tgt, str(rel.get("description", ""))))
                break

    # Group/software revocations are stored as STIX ids (no FK needed for those types).
    for rec in parsed.groups + parsed.software:
        rec["revoked_by_stix_id"] = parsed.revoked_by.get(rec["stix_id"], "")[:100]

    if not parsed.techniques or not parsed.tactics:
        raise BundleError("bundle contains no techniques or tactics for this domain")
    return parsed

"""Small synthetic ATT&CK STIX bundles for tests, shaped like the real v20 data.

``bundle_v1`` (19.0) and ``bundle_v2`` (20.0) differ in the ways that matter for re-import:
a technique is renamed, one is revoked with a replacement, a group stops using a technique,
a tactic drops out of the matrix, and a new sub-technique appears.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

T0 = "2024-01-01T00:00:00.000Z"


def _sid(kind: str, n: int) -> str:
    return f"{kind}--00000000-0000-4000-8000-{n:012d}"


def _refs(attack_id: str, path: str) -> list[dict[str, str]]:
    return [
        {
            "source_name": "mitre-attack",
            "external_id": attack_id,
            "url": f"https://attack.mitre.org/{path}",
        }
    ]


def _obj(kind: str, n: int, attack_id: str, path: str, name: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": _sid(kind, n),
        "created": T0,
        "modified": extra.pop("modified", T0),
        "name": name,
        "description": extra.pop("description", f"{name} description."),
        "external_references": _refs(attack_id, path),
        "x_mitre_domains": ["enterprise-attack"],
        "x_mitre_version": "1.0",
        "revoked": extra.pop("revoked", False),
        "x_mitre_deprecated": extra.pop("deprecated", False),
        **extra,
    }


def tactic(n: int, attack_id: str, shortname: str, name: str) -> dict[str, Any]:
    return _obj(
        "x-mitre-tactic", n, attack_id, f"tactics/{attack_id}", name, x_mitre_shortname=shortname
    )


def technique(
    n: int, attack_id: str, name: str, tactics: list[str], **extra: Any
) -> dict[str, Any]:
    sub = "." in attack_id
    return _obj(
        "attack-pattern",
        n,
        attack_id,
        "techniques/" + attack_id.replace(".", "/"),
        name,
        kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics],
        x_mitre_is_subtechnique=sub,
        x_mitre_platforms=extra.pop("platforms", ["Windows"]),
        **extra,
    )


def rel(n: int, rtype: str, src: str, tgt: str, desc: str = "", **extra: Any) -> dict[str, Any]:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _sid("relationship", n),
        "created": T0,
        "modified": T0,
        "relationship_type": rtype,
        "source_ref": src,
        "target_ref": tgt,
        "description": desc,
        **extra,
    }


def _meta(version: str, tactic_refs: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "type": "x-mitre-collection",
            "spec_version": "2.1",
            "id": _sid("x-mitre-collection", 1),
            "name": "Enterprise ATT&CK",
            "x_mitre_version": version,
            "x_mitre_attack_spec_version": "3.3.0",
            "created": T0,
            "modified": T0,
        },
        {
            "type": "x-mitre-matrix",
            "spec_version": "2.1",
            "id": _sid("x-mitre-matrix", 1),
            "name": "Enterprise ATT&CK",
            "tactic_refs": tactic_refs,
            "created": T0,
            "modified": T0,
        },
    ]


# Stable ids used across both versions
TA_IA, TA_EX, TA_ST = (
    _sid("x-mitre-tactic", 1),
    _sid("x-mitre-tactic", 2),
    _sid("x-mitre-tactic", 3),
)
T_PHISH = _sid("attack-pattern", 1)
T_PHISH_ATT = _sid("attack-pattern", 2)
T_CSI = _sid("attack-pattern", 3)
T_PS = _sid("attack-pattern", 4)
T_OLD_PS = _sid("attack-pattern", 5)  # revoked in v1 already (never created)
T_DEPR = _sid("attack-pattern", 6)  # deprecated in v1 already (never created)
T_PHISH_LINK = _sid("attack-pattern", 7)  # new in v2
G1 = _sid("intrusion-set", 1)
S1 = _sid("malware", 1)
M1 = _sid("course-of-action", 1)
M_DEPR = _sid("course-of-action", 2)
DET1 = _sid("x-mitre-detection-strategy", 1)
AN1 = _sid("x-mitre-analytic", 1)
DC1 = _sid("x-mitre-data-component", 1)


def bundle_v1() -> dict[str, Any]:
    objects = [
        *_meta("19.0", [TA_IA, TA_EX, TA_ST]),
        # Deliberately listed out of matrix order: order must come from the matrix.
        tactic(3, "TA0005", "stealth", "Stealth"),
        tactic(1, "TA0001", "initial-access", "Initial Access"),
        tactic(2, "TA0002", "execution", "Execution"),
        technique(1, "T1566", "Phishing", ["initial-access"], platforms=["Windows", "Linux"]),
        technique(2, "T1566.001", "Spearphishing Attachment", ["initial-access"]),
        technique(
            3,
            "T1059",
            "Command and Scripting Interpreter",
            ["execution"],
            platforms=["Windows", "Linux", "macOS"],
        ),
        technique(
            4,
            "T1059.001",
            "PowerShell",
            ["execution", "stealth"],
            description=(
                "Adversaries may abuse [PowerShell](https://attack.mitre.org/techniques/T1059/001)"
                " commands.(Citation: TechNet PowerShell)\n\nSee `powershell.exe`."
            ),
        ),
        technique(5, "T1086", "PowerShell (old)", ["execution"], revoked=True),
        technique(6, "T9999", "Old Deprecated Thing", ["execution"], deprecated=True),
        _obj(
            "intrusion-set",
            1,
            "G0001",
            "groups/G0001",
            "APT Test",
            aliases=["APT Test", "Fancy Test", "Test Bear"],
        ),
        _obj(
            "malware",
            1,
            "S0001",
            "software/S0001",
            "TestRAT",
            x_mitre_aliases=["TestRAT", "TRAT"],
            x_mitre_platforms=["Windows"],
        ),
        _obj("course-of-action", 1, "M1049", "mitigations/M1049", "Antivirus/Antimalware"),
        _obj(
            "course-of-action",
            2,
            "T1566-legacy",
            "mitigations/T1566",
            "Old mitigation",
            deprecated=True,
        ),
        _obj(
            "x-mitre-data-component",
            1,
            "DC0001",
            "datacomponents/DC0001",
            "Process Creation",
            x_mitre_log_sources=[{"name": "WinEventLog:Security", "channel": "EventCode=4688"}],
        ),
        _obj(
            "x-mitre-detection-strategy",
            1,
            "DET0001",
            "detectionstrategies/DET0001",
            "Detect suspicious PowerShell",
            x_mitre_analytic_refs=[AN1],
        ),
        _obj(
            "x-mitre-analytic",
            1,
            "AN0001",
            "detectionstrategies/DET0001#AN0001",
            "Analytic 0001",
            x_mitre_platforms=["Windows"],
            x_mitre_log_source_references=[
                {
                    "x_mitre_data_component_ref": DC1,
                    "name": "WinEventLog:Security",
                    "channel": "EventCode=4688",
                }
            ],
        ),
        rel(1, "subtechnique-of", T_PHISH_ATT, T_PHISH),
        rel(2, "subtechnique-of", T_PS, T_CSI),
        rel(3, "revoked-by", T_OLD_PS, T_PS),
        rel(
            4,
            "uses",
            G1,
            T_PHISH_ATT,
            "[APT Test](https://attack.mitre.org/groups/G0001) sends attachments.",
        ),
        rel(5, "uses", G1, T_PS, "APT Test runs PowerShell."),
        rel(6, "uses", G1, S1, "APT Test deploys TestRAT."),
        rel(7, "uses", S1, T_CSI, "TestRAT runs commands."),
        rel(8, "mitigates", M1, T_PHISH_ATT, "Scan attachments."),
        rel(9, "mitigates", M_DEPR, T_PHISH, "Deprecated mitigation link."),
        rel(10, "detects", DET1, T_PS),
        rel(11, "uses", G1, T_CSI, "Revoked relationship.", revoked=True),
    ]
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": objects,
    }


def bundle_v2() -> dict[str, Any]:
    b = bundle_v1()
    objs = b["objects"]
    objs[0]["x_mitre_version"] = "20.0"
    objs[1]["tactic_refs"] = [TA_IA, TA_EX]  # Stealth leaves the matrix
    for o in objs:
        if o["id"] == T_CSI:
            o["name"] = "Command and Scripting Interpreters"
            o["modified"] = "2025-06-01T00:00:00.000Z"
        if o["id"] == T_PHISH_ATT:
            o["revoked"] = True
    objs.append(technique(7, "T1566.002", "Spearphishing Link", ["initial-access"]))
    objs.append(rel(20, "subtechnique-of", T_PHISH_LINK, T_PHISH))
    objs.append(rel(21, "revoked-by", T_PHISH_ATT, T_PHISH_LINK))
    objs.append(rel(22, "uses", G1, T_PHISH_LINK, "APT Test sends links."))
    # Group no longer uses PowerShell; attachment links disappear with the revocation.
    drop = {_sid("relationship", 5), _sid("relationship", 4), _sid("relationship", 8)}
    b["objects"] = [o for o in objs if o["id"] not in drop]
    return b


def write(bundle: dict[str, Any], path: Path) -> Path:
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return path

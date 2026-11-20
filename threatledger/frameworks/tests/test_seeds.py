"""The shipped seed files must be valid and every seeded mapping must resolve."""

from __future__ import annotations

from io import StringIO

import pytest
import yaml
from django.core.management import call_command

from threatledger.controls.models import Control
from threatledger.controls.services import seed_starter_controls
from threatledger.frameworks import services
from threatledger.frameworks.importer import parse, validate
from threatledger.frameworks.models import ControlRequirement, Framework, RequirementMapping

EXPECTED = {
    "nist-800-53-r5.json": ("NIST-800-53-R5", 1014, "full"),
    "iso-27001-2022.yaml": ("ISO27001-2022", 93, "reference"),
    "soc2-tsc-2017.yaml": ("SOC2-TSC-2017", 61, "reference"),
    "cis-controls-v8.yaml": ("CIS-V8", 153, "reference"),
    "hipaa-security-rule.yaml": ("HIPAA-SR", 48, "summary"),
    "india-dpdp-2023.yaml": ("DPDP-2023", 20, "summary"),
}


@pytest.mark.parametrize("name", list(EXPECTED))
def test_seed_file_is_valid(name):
    doc = parse((services.DATA_DIR / name).read_bytes(), name)
    assert validate(doc) == []
    code, count, level = EXPECTED[name]
    assert doc.framework["code"] == code
    assert doc.framework["content_level"] == level
    assert sum(1 for r in doc.requirements if not r.get("is_domain")) == count
    assert all(isinstance(r["ref"], str) for r in doc.requirements)


def test_nist_seed_has_full_text_and_baselines():
    doc = parse((services.DATA_DIR / "nist-800-53-r5.json").read_bytes(), "n.json")
    reqs = {r["ref"]: r for r in doc.requirements}
    assert (
        "Implement multi-factor authentication for access to privileged accounts"
        in reqs["IA-2(1)"]["text"]
    )
    assert reqs["AC-2(1)"]["baselines"] == ["moderate", "high"]
    assert sum(1 for r in doc.requirements if "moderate" in r.get("baselines", [])) == 287


def test_licensed_frameworks_carry_no_text():
    for name in ("iso-27001-2022.yaml", "soc2-tsc-2017.yaml", "cis-controls-v8.yaml"):
        doc = parse((services.DATA_DIR / name).read_bytes(), name)
        assert not any(r.get("text") for r in doc.requirements), name


@pytest.mark.django_db
def test_seed_frameworks_resolves_every_mapping_and_is_idempotent(org):
    seed_starter_controls(org)
    report = services.seed_frameworks(org)
    assert Framework.objects.count() == 6
    starter = yaml.safe_load(services.STARTER_CONTROLS.read_text())
    expected_links = sum(
        len(refs) for c in starter["controls"] for refs in c["requirements"].values()
    )
    assert report.control_mappings_created == expected_links == ControlRequirement.objects.count()
    crosswalk = yaml.safe_load((services.DATA_DIR / "crosswalk.yaml").read_text())
    assert (
        report.crosswalk_created == len(crosswalk["mappings"]) == RequirementMapping.objects.count()
    )
    assert ControlRequirement.objects.filter(indicative=True).count() == expected_links
    again = services.seed_frameworks(org)
    assert again.crosswalk_created == again.control_mappings_created == 0
    assert all(f["created"] == 0 for f in again.frameworks)


@pytest.mark.django_db
def test_seeding_order_does_not_matter(org):
    services.seed_frameworks(org)  # frameworks first, no controls yet
    assert not ControlRequirement.objects.exists()
    result = seed_starter_controls(org)
    assert result.requirement_mappings > 100
    mfa = Control.objects.get(ref="CTL-MFA")
    assert set(mfa.requirement_links.values_list("requirement__framework__code", flat=True)) == {
        "NIST-800-53-R5", "ISO27001-2022", "SOC2-TSC-2017", "HIPAA-SR", "CIS-V8", "DPDP-2023"
    }  # fmt: skip


@pytest.mark.django_db
def test_seed_frameworks_command(org):
    out = StringIO()
    call_command("seed_frameworks", stdout=out)
    assert "INDICATIVE" in out.getvalue()
    assert "NIST-800-53-R5" in out.getvalue()

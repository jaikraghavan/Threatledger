from __future__ import annotations

import json
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from threatledger.frameworks.compliance import ReqStatus, Summary, requirement_status, summarise
from threatledger.frameworks.importer import FrameworkImportError, load, parse, validate
from threatledger.frameworks.models import Framework, Requirement

YAML = b"""
framework: {code: TEST-FW, name: Test framework, version: "1", content_level: summary}
requirements:
  - {ref: D1, title: Domain one, is_domain: true}
  - {ref: "1.1", title: First, text: Do the thing, parent: D1}
  - {ref: "1.10", title: Tenth, parent: D1}
  - {ref: 1.1(a), title: Enhancement, parent: "1.1"}
"""


# ----------------------------------------------------------------------------- pure rules
@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], ReqStatus.NO_CONTROL),
        (["implemented"], ReqStatus.MET),
        (["implemented", "implemented"], ReqStatus.MET),
        (["implemented", "planned"], ReqStatus.PARTIAL),
        (["partial"], ReqStatus.PARTIAL),
        (["planned", "not_implemented"], ReqStatus.GAP),
    ],
)
def test_requirement_status_rules(statuses, expected):
    assert requirement_status(statuses) is expected


def test_summary_percent_and_bar():
    s = summarise({1: ["implemented"], 2: ["partial"], 3: ["planned"]}, [1, 2, 3, 4])
    assert (s.met, s.partial, s.gap, s.no_control, s.tracked) == (1, 1, 1, 1, 4)
    assert s.percent == 37.5
    assert s.bar == [
        (0.0, 25.0, "fill-green-500"),
        (25.0, 25.0, "fill-amber-400"),
        (50.0, 25.0, "fill-red-400"),
    ]
    assert Summary().percent == 0.0
    assert Summary().bar == []
    assert ReqStatus.NO_CONTROL.label == "No control"


# ----------------------------------------------------------------------------- importer
def test_parse_yaml_json_csv():
    assert len(parse(YAML, "fw.yaml").requirements) == 4
    as_json = json.dumps(
        {"framework": {"code": "J", "name": "J"}, "requirements": [{"ref": "A", "title": "a"}]}
    )
    assert parse(as_json.encode(), "fw.json").framework["code"] == "J"
    csv_doc = parse(
        b"ref,title,text,parent,is_domain,baselines\nD,Dom,,,yes,\nD.1,One,txt,D,,low|high\n",
        "fw.csv",
        {"code": "CSV-FW", "name": "From CSV"},
    )
    assert csv_doc.framework == {"code": "CSV-FW", "name": "From CSV"}
    assert csv_doc.requirements[0]["is_domain"] is True
    assert csv_doc.requirements[1]["baselines"] == ["low", "high"]


@pytest.mark.parametrize(
    ("content", "name", "message"),
    [
        (b"\xff\xfe", "x.yaml", "UTF-8"),
        (b"framework: [", "x.yaml", "could not parse"),
        (b"[]", "x.json", "expected an object"),
        (b"a,b\n1,2", "x.csv", "columns: ref, title"),
    ],
)
def test_parse_errors(content, name, message):
    with pytest.raises(FrameworkImportError, match=message):
        parse(content, name)


def _doc(reqs, **fw):
    from threatledger.frameworks.importer import FrameworkDoc

    return FrameworkDoc({"code": "X-1", "name": "X", **fw}, reqs)


@pytest.mark.parametrize(
    ("reqs", "fw", "message"),
    [
        ([{"ref": "A", "title": "a"}], {"code": "bad code!"}, "framework.code"),
        ([{"ref": "A", "title": "a"}], {"content_level": "verbatim"}, "content_level"),
        ([{"ref": "A", "title": "a"}, {"ref": "A", "title": "b"}], {}, "duplicate ref A"),
        ([{"ref": "A", "title": ""}], {}, "title is required"),
        ([{"ref": "A", "title": "a", "parent": "Z"}], {}, "parent Z not found"),
        (
            [{"ref": "A", "title": "a", "parent": "B"}, {"ref": "B", "title": "b", "parent": "A"}],
            {},
            "cycle",
        ),
        ([{"ref": 3.1, "title": "float"}], {}, "quote numeric refs"),
        ([{"ref": "<script>", "title": "x"}], {}, "invalid ref"),
        ([{"ref": "D", "title": "d", "is_domain": True}], {}, "nothing to assess"),
        ([], {}, "no requirements"),
    ],
)
def test_validation_errors(reqs, fw, message):
    errors = validate(_doc(reqs, **fw))
    assert any(message in e for e in errors), errors


@pytest.mark.django_db
def test_load_is_idempotent_and_never_deletes():
    first = load(parse(YAML, "fw.yaml"))
    assert (first.created, first.updated) == (4, 0)
    fw = Framework.objects.get(code="TEST-FW")
    enh = Requirement.objects.get(framework=fw, ref="1.1(a)")
    assert enh.parent is not None
    assert enh.parent.ref == "1.1"
    assert (
        Requirement.objects.get(framework=fw, ref="1.10").title == "Tenth"
    )  # not "1.1" as a float
    again = load(parse(YAML, "fw.yaml"))
    assert (again.created, again.updated, again.unchanged) == (0, 0, 4)
    changed = YAML.replace(b"title: First", b"title: First (renamed)").replace(
        b'  - {ref: "1.10", title: Tenth, parent: D1}\n', b""
    )
    third = load(parse(changed, "fw.yaml"))
    assert third.updated == 2  # renamed "1.1", and "1.1(a)" moved up one position
    assert third.missing == ["1.10"]
    assert Requirement.objects.filter(framework=fw, ref="1.10").exists()  # kept


@pytest.mark.django_db
def test_dry_run_changes_nothing():
    result = load(parse(YAML, "fw.yaml"), dry_run=True)
    assert result.created == 4 and result.dry_run
    assert not Framework.objects.exists()


@pytest.mark.django_db
def test_import_framework_command(tmp_path):
    path = tmp_path / "fw.yaml"
    path.write_bytes(YAML)
    out = StringIO()
    call_command("import_framework", str(path), "--dry-run", stdout=out)
    assert "DRY RUN" in out.getvalue()
    call_command("import_framework", str(path), stdout=StringIO())
    assert Requirement.objects.count() == 4
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"framework: {code: x}\nrequirements: []\n")
    with pytest.raises(CommandError, match="validation error"):
        call_command("import_framework", str(bad), stdout=StringIO(), stderr=StringIO())
    csv_path = tmp_path / "p.csv"
    csv_path.write_text("ref,title\n1,Req one\n")
    call_command(
        "import_framework", str(csv_path), "--code", "PCI", "--name", "PCI DSS", stdout=StringIO()
    )
    assert Framework.objects.get(code="PCI").requirements.count() == 1

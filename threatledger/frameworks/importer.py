"""Framework import: JSON / YAML / CSV -> validated document -> idempotent upsert.

JSON/YAML schema (``threatledger-framework/1``)::

    framework:
      code: ISO27001-2022          # slug, unique
      name: ISO/IEC 27001:2022 Annex A
      version: "2022"
      publisher: ISO/IEC
      source_url: https://...
      licence_note: ...
      content_level: full | summary | reference
      description: ...
      baselines: [low, moderate, high]   # optional
    requirements:
      - ref: A.5                     # unique within the framework
        title: Organizational controls
        is_domain: true              # grouping node, not assessed
      - ref: A.5.1
        title: Information security policies
        text: ...                    # optional
        parent: A.5                  # optional, by ref (any order)
        baselines: [moderate]        # optional

CSV: one requirement per row with columns ``ref,title,text,parent,is_domain,baselines``
(``baselines`` separated by ``|``). Framework metadata is passed separately.

Requirements absent from a re-import are reported, never deleted (mappings point at them).
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any

import yaml
from django.db import transaction

from .models import ContentLevel, Framework, Requirement

MAX_REQUIREMENTS = 20_000
MAX_BYTES = 10 * 1024 * 1024
CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,39}$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .()\-_/:§]{0,63}$")
FRAMEWORK_FIELDS = (
    "name",
    "version",
    "publisher",
    "source_url",
    "licence_note",
    "description",
    "content_level",
    "baselines",
)


class FrameworkImportError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__(
            "; ".join(errors[:5]) + (f" (+{len(errors) - 5} more)" if len(errors) > 5 else "")
        )
        self.errors = errors


@dataclass
class FrameworkDoc:
    framework: dict[str, Any]
    requirements: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "y", "x")


def parse(data: bytes, filename: str, meta: dict[str, Any] | None = None) -> FrameworkDoc:
    if len(data) > MAX_BYTES:
        raise FrameworkImportError([f"file exceeds {MAX_BYTES // (1024 * 1024)} MB"])
    name = filename.lower()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise FrameworkImportError(["file is not UTF-8 text"]) from exc
    if name.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or not {"ref", "title"} <= set(reader.fieldnames):
            raise FrameworkImportError(["CSV needs at least the columns: ref, title"])
        reqs = []
        for row in reader:
            reqs.append(
                {
                    "ref": (row.get("ref") or "").strip(),
                    "title": (row.get("title") or "").strip(),
                    "text": (row.get("text") or "").strip(),
                    "parent": (row.get("parent") or "").strip() or None,
                    "is_domain": _truthy(row.get("is_domain", "")),
                    "baselines": [
                        b.strip() for b in (row.get("baselines") or "").split("|") if b.strip()
                    ],
                }
            )
        return FrameworkDoc(framework=dict(meta or {}), requirements=reqs)
    try:
        raw = json.loads(text) if name.endswith(".json") else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise FrameworkImportError([f"could not parse file: {exc}"]) from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("requirements"), list):
        raise FrameworkImportError(["expected an object with 'framework' and 'requirements'"])
    framework = dict(raw.get("framework") or {})
    framework.update({k: v for k, v in (meta or {}).items() if v})
    return FrameworkDoc(framework=framework, requirements=list(raw["requirements"]))


def validate(doc: FrameworkDoc) -> list[str]:
    errors: list[str] = []
    fw = doc.framework
    if not CODE_RE.match(str(fw.get("code", ""))):
        errors.append("framework.code is required (letters, digits, - or _, 2–40 chars)")
    if not str(fw.get("name", "")).strip():
        errors.append("framework.name is required")
    if fw.get("content_level", "reference") not in ContentLevel.values:
        errors.append(f"framework.content_level must be one of {', '.join(ContentLevel.values)}")
    if not doc.requirements:
        errors.append("no requirements")
    if len(doc.requirements) > MAX_REQUIREMENTS:
        errors.append(f"too many requirements (max {MAX_REQUIREMENTS})")
    refs: dict[str, dict[str, Any]] = {}
    for i, req in enumerate(doc.requirements, start=1):
        if not isinstance(req, dict):
            errors.append(f"requirement #{i}: not an object")
            continue
        if not isinstance(req.get("ref"), str):
            errors.append(
                f"requirement #{i}: ref must be text; quote numeric refs in YAML "
                f"(e.g. '3.10', which would otherwise be read as 3.1)"
            )
            continue
        ref = req["ref"].strip()
        if not REF_RE.match(ref):
            errors.append(f"requirement #{i}: invalid ref {ref!r}")
            continue
        if ref in refs:
            errors.append(f"duplicate ref {ref}")
        if not str(req.get("title", "")).strip():
            errors.append(f"{ref}: title is required")
        if len(str(req.get("title", ""))) > 500:
            errors.append(f"{ref}: title longer than 500 characters")
        if len(str(req.get("text", "") or "")) > 50_000:
            errors.append(f"{ref}: text longer than 50,000 characters")
        if req.get("baselines") is not None and not isinstance(req.get("baselines"), list):
            errors.append(f"{ref}: baselines must be a list")
        refs[ref] = req
    for ref, req in refs.items():
        parent = req.get("parent")
        if parent and parent not in refs:
            errors.append(f"{ref}: parent {parent} not found")
    # cycles
    for ref in refs:
        seen: set[str] = set()
        cur: str | None = ref
        while cur:
            if cur in seen:
                errors.append(f"{ref}: parent chain contains a cycle")
                break
            seen.add(cur)
            cur = (refs.get(cur) or {}).get("parent")
    if not any(not r.get("is_domain") for r in refs.values()):
        errors.append("every requirement is a domain; nothing to assess")
    return errors


@dataclass
class LoadResult:
    framework: Framework
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    missing: list[str] = field(default_factory=list)
    dry_run: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework.code,
            "created": self.created,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "missing": len(self.missing),
            "dry_run": self.dry_run,
        }


class _DryRunRollback(Exception):
    pass


def load(doc: FrameworkDoc, *, dry_run: bool = False, indicative: bool | None = None) -> LoadResult:
    errors = validate(doc)
    if errors:
        raise FrameworkImportError(errors)
    try:
        with transaction.atomic():
            result = _load(doc, indicative)
            result.dry_run = dry_run
            if dry_run:
                raise _DryRunRollback
    except _DryRunRollback:
        pass
    return result


def _load(doc: FrameworkDoc, indicative: bool | None) -> LoadResult:
    fw_data = doc.framework
    defaults = {k: fw_data[k] for k in FRAMEWORK_FIELDS if k in fw_data and fw_data[k] is not None}
    if indicative is not None:
        defaults["is_indicative"] = indicative
    framework, _ = Framework.objects.update_or_create(code=fw_data["code"], defaults=defaults)
    result = LoadResult(framework=framework)
    existing = {r.ref: r for r in Requirement.objects.filter(framework=framework)}
    seen: set[str] = set()
    created_refs: set[str] = set()
    to_update: list[Requirement] = []
    fields = ("title", "text", "order", "is_domain", "baselines")
    for order, item in enumerate(doc.requirements, start=1):
        ref = str(item["ref"]).strip()
        seen.add(ref)
        values = {
            "title": str(item["title"]).strip()[:500],
            "text": str(item.get("text") or "").strip(),
            "order": int(item.get("order") or order),
            "is_domain": bool(item.get("is_domain", False)),
            "baselines": list(item.get("baselines") or []),
        }
        obj = existing.get(ref)
        if obj is None:
            existing[ref] = Requirement.objects.create(framework=framework, ref=ref, **values)
            created_refs.add(ref)
            result.created += 1
        elif any(getattr(obj, f) != values[f] for f in fields):
            for f in fields:
                setattr(obj, f, values[f])
            to_update.append(obj)
            result.updated += 1
        else:
            result.unchanged += 1
    if to_update:
        Requirement.objects.bulk_update(to_update, list(fields), batch_size=500)
    parent_changes = []
    for item in doc.requirements:
        obj = existing[str(item["ref"]).strip()]
        parent = existing.get(item.get("parent") or "")
        parent_id = parent.pk if parent else None
        if obj.parent_id != parent_id:
            obj.parent_id = parent_id
            parent_changes.append(obj)
    if parent_changes:
        Requirement.objects.bulk_update(parent_changes, ["parent"], batch_size=500)
        already = {o.pk for o in to_update}
        moved_only = [
            o for o in parent_changes if o.ref not in created_refs and o.pk not in already
        ]
        result.updated += len(moved_only)
        result.unchanged -= len(moved_only)
    result.missing = sorted(set(existing) - seen)
    return result

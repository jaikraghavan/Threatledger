from __future__ import annotations

from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from threatledger.accounts.models import Membership, User
from threatledger.accounts.roles import Role
from threatledger.org.models import BusinessUnit, Organisation

pytestmark = pytest.mark.django_db


@override_settings(DEBUG=True)
def test_seed_creates_org_units_and_one_user_per_role(monkeypatch):
    monkeypatch.delenv("SEED_PASSWORD", raising=False)
    out = StringIO()
    call_command("seed", stdout=out)
    assert Organisation.objects.count() == 1
    assert BusinessUnit.objects.count() == 5
    assert {m.role for m in Membership.objects.all()} == set(Role.values)
    assert "passwords are shown only once" in out.getvalue()
    for user in User.objects.all():
        assert user.has_usable_password()


@override_settings(DEBUG=True)
def test_seed_is_idempotent(monkeypatch):
    monkeypatch.setenv("SEED_PASSWORD", "a-shared-demo-password")
    call_command("seed", stdout=StringIO())
    hashes = dict(User.objects.values_list("username", "password"))
    out = StringIO()
    call_command("seed", stdout=out)
    assert User.objects.count() == 5
    assert Organisation.objects.count() == 1
    assert dict(User.objects.values_list("username", "password")) == hashes
    assert "nothing to do" in out.getvalue()
    assert User.objects.get(username="admin").check_password("a-shared-demo-password")


@override_settings(DEBUG=False)
def test_seed_refuses_in_production_without_flag():
    with pytest.raises(CommandError, match="allow-production"):
        call_command("seed", stdout=StringIO())


@override_settings(DEBUG=False)
def test_seed_runs_in_production_with_flag():
    call_command("seed", "--allow-production", stdout=StringIO())
    assert User.objects.count() == 5

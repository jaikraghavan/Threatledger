from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError
from django.urls import reverse

from threatledger.accounts.models import Membership
from threatledger.accounts.permissions import business_unit_scope
from threatledger.accounts.roles import Role
from threatledger.org import services
from threatledger.org.models import BusinessUnit, descendant_ids, tree
from threatledger.risks.tests.helpers import make_risk

pytestmark = pytest.mark.django_db


@pytest.fixture
def admin(users):
    return users[Role.ADMIN]


def test_tree_and_descendants(org):
    emea = BusinessUnit.objects.create(organisation=org, name="EMEA")
    uk = BusinessUnit.objects.create(organisation=org, name="UK", parent=emea)
    ldn = BusinessUnit.objects.create(organisation=org, name="London", parent=uk)
    apac = BusinessUnit.objects.create(organisation=org, name="APAC")
    assert descendant_ids(org.pk, {emea.pk}) == {emea.pk, uk.pk, ldn.pk}
    assert [(bu.name, d) for bu, d in tree(org.pk)] == [
        ("APAC", 0),
        ("EMEA", 0),
        ("UK", 1),
        ("London", 2),
    ]
    assert descendant_ids(org.pk, {apac.pk}) == {apac.pk}


def test_membership_scope_covers_sub_units(org, make_user, users):
    emea = BusinessUnit.objects.create(organisation=org, name="EMEA")
    uk = BusinessUnit.objects.create(organisation=org, name="UK", parent=emea)
    apac = BusinessUnit.objects.create(organisation=org, name="APAC")
    scoped = make_user(Role.RISK_MANAGER, username="emea")
    Membership.objects.get(user=scoped).business_units.set([emea])
    assert business_unit_scope(scoped) == frozenset({emea.pk, uk.pk})
    from threatledger.risks.services import visible_risks

    risk_uk = make_risk(users[Role.ADMIN], business_unit=uk)
    risk_apac = make_risk(users[Role.ADMIN], business_unit=apac)
    visible = set(visible_risks(scoped))
    assert risk_uk in visible and risk_apac not in visible


def test_cycles_are_rejected(org, admin):
    a = services.create_business_unit(user=admin, data={"name": "A"})
    b = services.create_business_unit(user=admin, data={"name": "B", "parent": a})
    with pytest.raises(ValidationError):
        services.update_business_unit(a, user=admin, data={"parent": b})
    with pytest.raises(ValidationError):
        services.update_business_unit(a, user=admin, data={"parent": a})


def test_only_admins_manage_units(users):
    for role in (Role.RISK_MANAGER, Role.AUDITOR):
        with pytest.raises(services.OrgError):
            services.create_business_unit(user=users[role], data={"name": "X"})


def test_delete_rules(org, admin, users):
    parent = services.create_business_unit(user=admin, data={"name": "P"})
    child = services.create_business_unit(user=admin, data={"name": "C", "parent": parent})
    with pytest.raises(services.OrgError, match="sub-units"):
        services.delete_business_unit(parent, user=admin)
    make_risk(admin, business_unit=child)
    with pytest.raises(services.OrgError, match="still used"):
        services.delete_business_unit(child, user=admin)
    empty = services.create_business_unit(user=admin, data={"name": "Empty"})
    services.delete_business_unit(empty, user=admin)
    assert not BusinessUnit.objects.filter(name="Empty").exists()


def test_views(client_for, org):
    c = client_for(Role.ADMIN)
    assert c.get(reverse("org:units")).status_code == 200
    c.post(reverse("org:unit_create"), {"name": "EMEA", "code": "EM"})
    emea = BusinessUnit.objects.get(name="EMEA")
    c.post(reverse("org:unit_create"), {"name": "UK", "parent": emea.pk})
    uk = BusinessUnit.objects.get(name="UK")
    r = c.post(reverse("org:unit_edit", args=[emea.pk]), {"name": "EMEA", "parent": uk.pk})
    assert r.status_code == 200 and b"inside itself" in r.content
    page = c.get(reverse("org:units"))
    assert b"pl-6" in page.content  # UK is indented under EMEA
    assert c.get(reverse("org:unit_delete", args=[uk.pk])).status_code == 403  # POST only
    c.post(reverse("org:unit_delete", args=[uk.pk]))
    assert not BusinessUnit.objects.filter(name="UK").exists()
    assert client_for(Role.RISK_MANAGER).get(reverse("org:units")).status_code == 403

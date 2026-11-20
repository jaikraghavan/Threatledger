from __future__ import annotations

from collections.abc import Callable

import pytest
from django.test import Client

from threatledger.accounts.models import Membership, User
from threatledger.accounts.roles import Role
from threatledger.org.models import Organisation

TEST_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def org(db) -> Organisation:
    return Organisation.objects.create(name="Acme Ltd")


@pytest.fixture
def make_user(org) -> Callable[..., User]:
    def _make(role: Role | None = Role.VIEWER, username: str | None = None, **extra) -> User:
        name = username or (role.value if role else "norole")
        user = User.objects.create_user(
            username=name, email=f"{name}@example.com", password=TEST_PASSWORD, **extra
        )
        if role is not None:
            Membership.objects.create(user=user, organisation=org, role=role)
        return user

    return _make


@pytest.fixture
def users(make_user) -> dict[Role, User]:
    return {role: make_user(role) for role in Role}


@pytest.fixture
def client_for(users) -> Callable[[Role], Client]:
    def _client(role: Role) -> Client:
        c = Client()
        c.force_login(users[role])
        return c

    return _client

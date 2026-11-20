"""Create an organisation, business units and one user per role. Idempotent.

Passwords come from ``$SEED_PASSWORD`` if set, otherwise a random password per user is
generated and printed once. Existing users keep their passwords.
"""

from __future__ import annotations

import os
import secrets
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction

from threatledger.accounts.models import Membership, User
from threatledger.accounts.roles import Role
from threatledger.audit.models import Action
from threatledger.audit.services import record
from threatledger.org.models import BusinessUnit, Organisation

BUSINESS_UNITS = [
    ("Corporate", "CORP"),
    ("Engineering", "ENG"),
    ("Operations", "OPS"),
    ("Finance", "FIN"),
    ("Customer Services", "CS"),
]

SEED_USERS = [
    ("admin", "Ada", "Admin", Role.ADMIN),
    ("riskmanager", "Rhea", "Manager", Role.RISK_MANAGER),
    ("controlowner", "Cyrus", "Owner", Role.CONTROL_OWNER),
    ("auditor", "Aditi", "Auditor", Role.AUDITOR),
    ("viewer", "Vik", "Viewer", Role.VIEWER),
]


class Command(BaseCommand):
    help = "Seed an organisation, business units and one user per role (idempotent)."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--org-name", default="Demo Organisation")
        parser.add_argument("--email-domain", default="example.com")
        parser.add_argument(
            "--allow-production",
            action="store_true",
            help="Required when DEBUG is off, to avoid creating demo accounts by accident.",
        )

    @transaction.atomic
    def handle(self, *args: Any, **opts: Any) -> None:
        if not settings.DEBUG and not opts["allow_production"]:
            raise CommandError(
                "DEBUG is off. Re-run with --allow-production if you really mean it."
            )

        org = Organisation.objects.current()
        if org is None:
            org = Organisation.objects.create(name=opts["org_name"])
            record(Action.CREATE, org, changes={"name": [None, org.name]})
            self.stdout.write(f"Created organisation {org.name}")

        for name, code in BUSINESS_UNITS:
            BusinessUnit.objects.get_or_create(organisation=org, name=name, defaults={"code": code})

        shared = os.environ.get("SEED_PASSWORD") or None
        created: list[tuple[str, str, str]] = []
        for username, first, last, role in SEED_USERS:
            user, is_new = User.objects.get_or_create(
                username=username,
                defaults={
                    "first_name": first,
                    "last_name": last,
                    "email": f"{username}@{opts['email_domain']}",
                },
            )
            if is_new:
                password = shared or secrets.token_urlsafe(12)
                user.set_password(password)
                user.save(update_fields=["password"])
                record(Action.CREATE, user, changes={"username": [None, username]})
                created.append(
                    (username, role.label, "(from SEED_PASSWORD)" if shared else password)
                )
            Membership.objects.update_or_create(
                user=user, organisation=org, defaults={"role": role}
            )

        if created:
            self.stdout.write("Created users (passwords are shown only once):")
            for username, label, password in created:
                self.stdout.write(f"  {username:<14} {label:<22} {password}")
        else:
            self.stdout.write("All seed users already exist; nothing to do.")
        self.stdout.write(self.style.SUCCESS("Seed complete."))

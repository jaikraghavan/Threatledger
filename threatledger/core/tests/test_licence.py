"""AGPL-3.0 §13: every page offers network users a link to the Corresponding Source."""

from pathlib import Path

import pytest
from django.conf import settings
from django.test import Client, override_settings

from threatledger.accounts.roles import Role

ROOT = Path(settings.BASE_DIR)


def test_licence_file_is_agpl_v3():
    text = (ROOT / "LICENSE").read_text()
    assert text.lstrip().startswith("GNU AFFERO GENERAL PUBLIC LICENSE")
    assert "Version 3, 19 November 2007" in text


@pytest.mark.django_db
@override_settings(SOURCE_CODE_URL="https://example.test/my-fork")
def test_sign_in_page_links_to_source():
    body = Client().get("/accounts/login/").content.decode()
    assert 'href="https://example.test/my-fork"' in body
    assert "GNU AGPL v3" in body


@pytest.mark.django_db
@override_settings(SOURCE_CODE_URL="https://example.test/my-fork")
def test_app_pages_link_to_source(client_for):
    body = client_for(Role.VIEWER).get("/").content.decode()
    assert 'href="https://example.test/my-fork"' in body

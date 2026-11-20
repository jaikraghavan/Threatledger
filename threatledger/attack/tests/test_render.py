from __future__ import annotations

import pytest

from threatledger.attack.templatetags.attack import attack_plain, render_attack_text


def test_escapes_html():
    html = render_attack_text('<script>alert("x")</script> & <img src=x onerror=alert(1)>')
    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html
    assert "&amp;" in html


@pytest.mark.parametrize(
    "md",
    [
        "[click](javascript:alert(1))",
        "[click](data:text/html;base64,PHNjcmlwdD4=)",
        '[x](https://ok.example/" onmouseover="alert(1))',
    ],
)
def test_unsafe_links_are_not_linked(md):
    html = render_attack_text(md)
    assert "<a " not in html  # rendered as escaped text, never as a link
    assert 'onmouseover="' not in html


def test_attack_links_rewritten_to_internal_pages():
    html = render_attack_text(
        "[PowerShell](https://attack.mitre.org/techniques/T1059/001) by "
        "[APT28](https://attack.mitre.org/groups/G0007) and [T1566](https://attack.mitre.org/techniques/T1566)"
    )
    assert 'href="/attack/techniques/T1059.001/"' in html
    assert 'href="/attack/groups/G0007/"' in html
    assert 'href="/attack/techniques/T1566/"' in html
    assert "target=" not in html.split("G0007")[0].split("T1059.001")[1]


def test_external_links_open_safely():
    html = render_attack_text("[Report](https://example.com/report?a=1&b=2)")
    assert 'href="https://example.com/report?a=1&amp;b=2"' in html
    assert 'rel="noopener noreferrer nofollow"' in html


def test_citations_removed_code_and_paragraphs():
    html = render_attack_text(
        "Uses `cmd.exe /c`.(Citation: Some Report 2020)\n\nSecond line\nthird"
    )
    assert "Citation" not in html
    assert "<code>cmd.exe /c</code>" in html
    assert html.count("<p>") == 2
    assert "Second line<br>third" in html


def test_empty():
    assert render_attack_text(None) == ""
    assert render_attack_text("") == ""


def test_plain_text():
    assert (
        attack_plain("[APT28](https://attack.mitre.org/groups/G0007) phish.(Citation: X)")
        == "APT28 phish."
    )
    assert attack_plain(None) == ""

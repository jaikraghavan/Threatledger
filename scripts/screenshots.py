"""Capture the README screenshots from a running ThreatLedger instance (dev tool).

Usage (against a demo instance, e.g. `make run` after `seed_demo`):

    uv run python scripts/screenshots.py --base-url http://127.0.0.1:8000 \
        --username riskmanager --password "$SEED_PASSWORD"

Signs in through the real login form, visits each page at 1440×900 and writes PNGs to
docs/screenshots/. It also fails if any page logs a browser console error or a CSP
violation, so it doubles as an end-to-end check that the UI works under the strict CSP.
Requires the dev dependency `playwright` and `uv run playwright install chromium`.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from playwright.sync_api import ConsoleMessage, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
PAGES = [
    ("dashboard", "/"),
    ("coverage", "/coverage/?scope=sector&value=financial"),
    ("risk-detail", "/risks/R-0001/"),
    ("compliance", "/frameworks/"),
    ("cross-framework", "/frameworks/cross/"),
    ("board-report", "/reports/board/"),
    ("audit", "/audits/A-0001/"),
    ("findings", "/findings/"),
    ("policy", "/policies/POL-002/"),
    ("task-board", "/work/board/"),
    ("approvals", "/work/approvals/"),
    ("my-work", "/work/"),
]
# Visited for the console/CSP check only (no screenshot).
CHECK_ONLY = [
    "/audits/",
    "/audits/campaigns/",
    "/audits/campaigns/C-0001/",
    "/findings/exceptions/",
    "/findings/exceptions/EX-0001/",
    "/findings/F-0001/",
    "/policies/",
    "/controls/CTL-MFA/",
    "/controls/CTL-HARDEN/",
    "/work/tasks/",
    "/work/tasks/T-0001/",
    "/work/questionnaires/",
    "/work/questionnaires/Q-001/",
    "/work/answers/QA-0001/",
    "/work/notifications/?all=1",
    "/work/preferences/",
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="riskmanager")
    parser.add_argument("--password", default=os.environ.get("SCREENSHOT_PASSWORD", ""))
    parser.add_argument("--out", default=str(ROOT / "docs" / "screenshots"))
    parser.add_argument("--width", type=int, default=1440)
    parser.add_argument("--height", type=int, default=900)
    args = parser.parse_args()
    if not args.password:
        parser.error("--password (or SCREENSHOT_PASSWORD) is required")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    base = args.base_url.rstrip("/")
    problems: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(
            viewport={"width": args.width, "height": args.height}, device_scale_factor=1
        )
        page = context.new_page()
        current = {"url": ""}

        def on_console(msg: ConsoleMessage) -> None:
            if msg.type == "error":
                problems.append(f"{current['url']}: console error: {msg.text}")

        page.on("console", on_console)
        page.on("pageerror", lambda exc: problems.append(f"{current['url']}: page error: {exc}"))

        current["url"] = "/accounts/login/"
        page.goto(f"{base}/accounts/login/")
        page.fill("#id_username", args.username)
        page.fill("#id_password", args.password)
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle")
        if "/accounts/login/" in page.url:
            print("login failed: check the username and password", file=sys.stderr)
            return 1

        for name, path in PAGES:
            current["url"] = path
            response = page.goto(f"{base}{path}")
            page.wait_for_load_state("networkidle")
            status = response.status if response else 0
            if status != 200:
                problems.append(f"{path}: HTTP {status}")
            target = out / f"{name}.png"
            page.screenshot(path=str(target))
            shown = target.relative_to(ROOT) if target.is_relative_to(ROOT) else target
            print(f"{status} {path} -> {shown}")
        for path in CHECK_ONLY:
            current["url"] = path
            response = page.goto(f"{base}{path}")
            page.wait_for_load_state("networkidle")
            status = response.status if response else 0
            if status != 200:
                problems.append(f"{path}: HTTP {status}")
            print(f"{status} {path} (checked)")
        browser.close()

    for problem in problems:
        print(f"PROBLEM {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""OSINT-X command-line interface.

Examples:
    python osint.py username example_user --format json
    python osint.py email person@example.com --format md
    python osint.py domain example.com --format html -o report.html
    python osint.py company example.com
    python osint.py delete <investigation_id>
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from analyzers.correlation import run_investigation
from database.database import delete_investigation, init_db, save_investigation
from database.models import InvestigationScope
from reports.html_report import generate_html_report
from reports.json_report import generate_json_report
from reports.markdown_report import generate_markdown_report
from utils.logger import get_logger
from utils.validators import (
    ValidationError,
    validate_domain,
    validate_email,
    validate_username,
)

logger = get_logger("osint-x-cli")

FORMAT_GENERATORS = {
    "json": generate_json_report,
    "md": generate_markdown_report,
    "html": generate_html_report,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="osint.py", description="OSINT-X CLI")
    sub = parser.add_subparsers(dest="mode", required=True)

    for mode, validator in [
        ("username", validate_username),
        ("email", validate_email),
        ("domain", validate_domain),
        ("github", validate_username),
        ("company", None),
    ]:
        p = sub.add_parser(mode)
        p.add_argument("value")
        p.add_argument("--format", choices=["json", "md", "html"], default="md")
        p.add_argument("-o", "--output", help="Write report to this file instead of stdout")
        p.add_argument("--modules", nargs="*", help="Restrict to specific modules")
        p.add_argument("--investigator", default="cli-user")
        p.add_argument("-v", "--verbose", action="store_true")

    del_parser = sub.add_parser("delete")
    del_parser.add_argument("investigation_id")

    return parser


async def main_async(args: argparse.Namespace) -> int:
    if args.mode == "delete":
        init_db()
        ok = delete_investigation(args.investigation_id)
        print("Deleted." if ok else "No such investigation.")
        return 0 if ok else 1

    scope_kwargs: dict = {}
    try:
        if args.mode == "username":
            scope_kwargs["username"] = validate_username(args.value)
        elif args.mode == "github":
            scope_kwargs["username"] = validate_username(args.value)
        elif args.mode == "email":
            scope_kwargs["email"] = validate_email(args.value)
        elif args.mode == "domain":
            scope_kwargs["domain"] = validate_domain(args.value)
        elif args.mode == "company":
            scope_kwargs["company"] = args.value
    except ValidationError as exc:
        print(f"Invalid input: {exc}", file=sys.stderr)
        return 2

    modules = args.modules
    if not modules:
        modules = {
            "username": ["username", "github"],
            "github": ["github"],
            "email": ["email"],
            "domain": ["domain"],
            "company": ["company"],
        }[args.mode]

    scope = InvestigationScope(modules=modules, **scope_kwargs)

    if args.verbose:
        logger.setLevel("DEBUG")

    init_db()
    investigation = await run_investigation(scope, investigator=args.investigator)
    save_investigation(investigation)

    report = FORMAT_GENERATORS[args.format](investigation)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"Investigation {investigation.id} written to {args.output}")
    else:
        print(report)

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())

# OmniTune - Personal Offline Music Server
# Copyright (C) 2026-Present  DarThunder
# SPDX-License-Identifier: AGPL-3.0-or-later.

import argparse
import datetime
from pathlib import Path

SKIP_DIRS = {".venv", "__pycache__", ".git", "node_modules", "model", "static"}


def build_header(project: str, author: str, license_id: str, year: str) -> str:
    return (
        f"# {project}\n"
        f"# Copyright (C) {year}-Present  {author}\n"
        f"# SPDX-License-Identifier: {license_id}\n"
    )


def already_has_header(text: str) -> bool:
    head = "\n".join(text.splitlines()[:5])
    return "SPDX-License-Identifier" in head


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def main():
    parser = argparse.ArgumentParser(description="Add a license header to all .py files.")
    parser.add_argument("--project", required=True, help="Project name, e.g. 'OmniTune'")
    parser.add_argument("--author", required=True, help="Copyright holder name")
    parser.add_argument("--license", required=True, help="SPDX license identifier, e.g. 'AGPL-3.0-or-later.'")
    parser.add_argument("--year", default=str(datetime.date.today().year), help="Copyright start year")
    parser.add_argument("--root", default=".", help="Root directory to walk (default: current dir)")
    parser.add_argument("--dry-run", action="store_true", help="List files that would change, don't write anything")
    args = parser.parse_args()

    header = build_header(args.project, args.author, args.license, args.year)
    root = Path(args.root).resolve()

    changed, skipped = [], []

    for py_file in root.rglob("*.py"):
        if should_skip(py_file.relative_to(root)):
            continue

        text = py_file.read_text(encoding="utf-8")

        if already_has_header(text):
            skipped.append(py_file)
            continue

        changed.append(py_file)
        if not args.dry_run:
            if text.startswith("#!"):
                first_line, rest = text.split("\n", 1)
                new_text = f"{first_line}\n{header}\n{rest}"
            else:
                new_text = f"{header}\n{text}"
            py_file.write_text(new_text, encoding="utf-8")

    verb = "Would update" if args.dry_run else "Updated"
    print(f"{verb} {len(changed)} file(s):")
    for f in changed:
        print(f"  + {f.relative_to(root)}")

    if skipped:
        print(f"\nSkipped {len(skipped)} file(s) that already had a header:")
        for f in skipped:
            print(f"  = {f.relative_to(root)}")


if __name__ == "__main__":
    main()
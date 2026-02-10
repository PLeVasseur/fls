#!/usr/bin/env -S uv run
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha1
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
SRC_DIR = ROOT / "src"
EXCLUDED_DOCS = {"glossary.rst", "index.rst", "changelog.rst"}
DT_RE = re.compile(r":dt:`([^`]+)`")
DC_RE = re.compile(r":dc:`([^`]+)`")
SPLIT_NUMBERS = re.compile(r"([0-9]+)")


def load_definitions_module():
    exts_path = str(ROOT / "exts")
    if exts_path not in sys.path:
        sys.path.append(exts_path)

    from ferrocene_spec.definitions import (  # pylint: disable=import-outside-toplevel
        id_from_text,
        parse_target_from_text,
    )

    return id_from_text, parse_target_from_text


id_from_text, parse_target_from_text = load_definitions_module()


@dataclass
class GlossaryEntry:
    term: str
    term_id: str
    kind: str
    body_lines: list[str]
    source_file: str
    source_line: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", default="src", help="Source directory")
    parser.add_argument(
        "--output",
        default="build/generated.glossary.rst",
        help="Generated glossary output path",
    )
    return parser.parse_args()


def paragraph_bounds(lines: list[str], index: int) -> tuple[int, int]:
    start = index
    while start > 0 and lines[start - 1].strip() != "":
        start -= 1

    end = index
    while end + 1 < len(lines) and lines[end + 1].strip() != "":
        end += 1

    return start, end


def strip_dp_line(lines: list[str]) -> list[str]:
    if lines and lines[0].strip().startswith(":dp:`"):
        return lines[1:]
    return lines


def replace_first_role(
    lines: list[str], source_role: str, target_role: str
) -> list[str]:
    needle = f":{source_role}:`"
    replacement = f":{target_role}:`"
    updated = list(lines)

    for index, line in enumerate(updated):
        if needle in line:
            updated[index] = line.replace(needle, replacement, 1)
            return updated

    return updated


def natural_sort_key(term: str) -> list[object]:
    return [
        int(fragment) if fragment.isdigit() else fragment.casefold()
        for fragment in SPLIT_NUMBERS.split(term)
    ]


def deterministic_id(prefix: str, kind: str, term_id: str) -> str:
    digest = sha1(f"{prefix}:{kind}:{term_id}".encode("utf-8")).hexdigest()
    return f"fls_{digest[:12]}"


def body_starts_with_list_item_dp(body_lines: list[str]) -> bool:
    for line in body_lines:
        stripped = line.lstrip()
        if not stripped:
            continue
        return bool(re.match(r"(\*|\-|#\.)\s+:dp:`", stripped))
    return False


def collect_entries(src: Path) -> list[GlossaryEntry]:
    entries: dict[tuple[str, str], GlossaryEntry] = {}

    for path in sorted(src.glob("*.rst")):
        if path.name in EXCLUDED_DOCS:
            continue

        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            matches = []
            matches.extend(
                ("term", match.group(1).strip()) for match in DT_RE.finditer(line)
            )
            matches.extend(
                ("code", match.group(1).strip()) for match in DC_RE.finditer(line)
            )
            if not matches:
                continue

            start, end = paragraph_bounds(lines, index)
            paragraph_lines = strip_dp_line(lines[start : end + 1])
            if not paragraph_lines:
                continue

            for kind, raw in matches:
                term, target = parse_target_from_text(raw)
                term_id = id_from_text("term", target)
                key = (kind, term_id)
                if key in entries:
                    continue

                body_lines = list(paragraph_lines)
                if kind == "term":
                    body_lines = replace_first_role(body_lines, "dt", "t")
                else:
                    body_lines = replace_first_role(body_lines, "dc", "c")

                body_lines = [
                    line.replace(":dt:`", ":t:`").replace(":dc:`", ":c:`")
                    for line in body_lines
                ]

                entries[key] = GlossaryEntry(
                    term=term,
                    term_id=term_id,
                    kind=kind,
                    body_lines=body_lines,
                    source_file=path.as_posix(),
                    source_line=index + 1,
                )

    return sorted(
        entries.values(), key=lambda item: (natural_sort_key(item.term), item.term)
    )


def render_entries(entries: list[GlossaryEntry]) -> list[str]:
    output = []

    for entry in entries:
        section_id = deterministic_id("section", entry.kind, entry.term_id)
        heading = "^" * len(entry.term)

        body_lines = list(entry.body_lines)
        if not body_starts_with_list_item_dp(body_lines):
            paragraph_id = deterministic_id("paragraph", entry.kind, entry.term_id)
            body_lines = [f":dp:`{paragraph_id}`", *body_lines]

        output.extend(
            [
                f".. _{section_id}:",
                "",
                entry.term,
                heading,
                "",
                *body_lines,
                "",
            ]
        )

    while output and output[-1] == "":
        output.pop()

    return output


def main() -> int:
    args = parse_args()
    src = (ROOT / args.src).resolve()
    output = (ROOT / args.output).resolve()

    entries = collect_entries(src)
    rendered = render_entries(entries)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(rendered) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

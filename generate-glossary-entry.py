#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys


DP_RE = re.compile(r":dp:`(?P<id>[^`]+)`")

DIRECTIVE_INDENT = 3
CONTENT_INDENT = 5


@dataclass
class GlossaryStaticEntry:
    term: str
    body_lines: list[str]


@dataclass
class EntryHeader:
    start: int
    term: str
    header_end: int


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a formatted glossary-entry directive for a term."
    )
    parser.add_argument("--term", required=True, help="Glossary term")
    parser.add_argument("--repo-root", default=".", help="Repo root directory")
    parser.add_argument(
        "--glossary",
        default="src/glossary.static.rst.inc",
        help="Static glossary file",
    )
    parser.add_argument(
        "--glossary-line",
        action="append",
        default=[],
        help="Glossary text line (repeatable)",
    )
    parser.add_argument(
        "--glossary-text-file",
        help="File with glossary body lines",
    )
    parser.add_argument(
        "--glossary-stdin",
        action="store_true",
        help="Read glossary body lines from stdin",
    )
    parser.add_argument("--chapter-file", help="Chapter file to extract from")
    parser.add_argument(
        "--chapter-dp",
        action="append",
        default=[],
        help="Chapter :dp: ids to extract (repeatable)",
    )
    parser.add_argument(
        "--chapter-line",
        action="append",
        default=[],
        help="Chapter text line (repeatable)",
    )
    parser.add_argument(
        "--chapter-text-file",
        help="File with chapter body lines",
    )
    parser.add_argument(
        "--chapter-stdin",
        action="store_true",
        help="Read chapter body lines from stdin",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    glossary_path = repo_root / args.glossary

    glossary_lines = resolve_block_lines(
        glossary_path,
        args.term,
        args.glossary_line,
        args.glossary_text_file,
        args.glossary_stdin,
    )
    if not glossary_lines:
        print("error: glossary lines are empty", file=sys.stderr)
        return 1

    chapter_lines = resolve_chapter_lines(
        repo_root,
        args.chapter_file,
        args.chapter_dp,
        args.chapter_line,
        args.chapter_text_file,
        args.chapter_stdin,
    )

    output_lines = render_entry(args.term, glossary_lines, chapter_lines)
    print("\n".join(output_lines))
    return 0


def resolve_block_lines(
    glossary_path: Path,
    term: str,
    line_args: list[str],
    text_file: str | None,
    stdin_flag: bool,
) -> list[str]:
    manual_lines = load_manual_lines(line_args, text_file, stdin_flag, "glossary")
    if manual_lines is not None:
        return trim_trailing_blanks(manual_lines)

    if not glossary_path.is_file():
        print(f"error: missing glossary file at {glossary_path}", file=sys.stderr)
        raise SystemExit(1)

    entries = parse_glossary_static(glossary_path)
    entry = entries.get(term)
    if entry is None:
        print(f"error: term not found in glossary: {term}", file=sys.stderr)
        raise SystemExit(1)
    return trim_trailing_blanks(entry.body_lines)


def resolve_chapter_lines(
    repo_root: Path,
    chapter_file: str | None,
    chapter_dp: list[str],
    line_args: list[str],
    text_file: str | None,
    stdin_flag: bool,
) -> list[str] | None:
    manual_lines = load_manual_lines(line_args, text_file, stdin_flag, "chapter")
    if manual_lines is not None:
        return trim_trailing_blanks(manual_lines)

    if chapter_file is None and not chapter_dp:
        return None
    if chapter_file is None or not chapter_dp:
        print(
            "error: --chapter-file and --chapter-dp must be provided together",
            file=sys.stderr,
        )
        raise SystemExit(1)

    path = (repo_root / chapter_file).resolve()
    if not path.is_file():
        print(f"error: missing chapter file at {path}", file=sys.stderr)
        raise SystemExit(1)

    lines = read_lines(path)
    blocks: list[str] = []
    for dp_id in chapter_dp:
        start = find_dp_line_index(lines, dp_id)
        if start is None:
            print(f"error: :dp: {dp_id} not found in {chapter_file}", file=sys.stderr)
            raise SystemExit(1)
        end = find_block_end(lines, start)
        blocks.extend(dedent_block(lines[start:end]))
    return trim_trailing_blanks(blocks)


def load_manual_lines(
    line_args: list[str],
    text_file: str | None,
    stdin_flag: bool,
    label: str,
) -> list[str] | None:
    sources = [bool(line_args), bool(text_file), stdin_flag]
    if sum(sources) > 1:
        print(f"error: multiple {label} sources provided", file=sys.stderr)
        raise SystemExit(1)
    if line_args:
        return list(line_args)
    if text_file:
        return read_lines(Path(text_file))
    if stdin_flag:
        return sys.stdin.read().splitlines()
    return None


def render_entry(
    term: str, glossary_lines: list[str], chapter_lines: list[str] | None
) -> list[str]:
    output: list[str] = [f".. glossary-entry:: {term}", " " * DIRECTIVE_INDENT]
    output.append(" " * DIRECTIVE_INDENT + ":glossary:")
    output.extend(indent_block(glossary_lines, CONTENT_INDENT))
    if chapter_lines is not None:
        output.append(" " * DIRECTIVE_INDENT + ":chapter:")
        output.extend(indent_block(chapter_lines, CONTENT_INDENT))
    return output


def indent_block(lines: list[str], indent: int) -> list[str]:
    prefix = " " * indent
    output: list[str] = []
    for line in lines:
        if line == "":
            output.append(prefix)
        else:
            output.append(prefix + line)
    return output


def dedent_block(lines: list[str]) -> list[str]:
    indents = [len(line) - len(line.lstrip(" ")) for line in lines if line.strip()]
    indent = min(indents) if indents else 0
    return [line[indent:] if len(line) >= indent else "" for line in lines]


def find_dp_line_index(lines: list[str], dp_id: str) -> int | None:
    target = f":dp:`{dp_id}`"
    for index, line in enumerate(lines):
        if target in line:
            return index
    return None


def find_block_end(lines: list[str], start_index: int) -> int:
    index = start_index + 1
    while index < len(lines):
        if index != start_index and is_dp_line(lines[index]):
            break
        index += 1
    return index


def is_dp_line(line: str) -> bool:
    stripped = line.lstrip()
    if stripped.startswith("* - "):
        stripped = stripped[4:]
    elif stripped.startswith("* "):
        stripped = stripped[2:]
    elif stripped.startswith("- "):
        stripped = stripped[2:]
    elif stripped.startswith("#. "):
        stripped = stripped[3:]
    return stripped.startswith(":dp:`")


def parse_glossary_static(path: Path) -> dict[str, GlossaryStaticEntry]:
    lines = read_lines(path)
    headers: list[EntryHeader] = []
    for index in range(len(lines)):
        header = parse_entry_header(lines, index)
        if header is not None:
            headers.append(header)

    entries: dict[str, GlossaryStaticEntry] = {}
    for pos, header in enumerate(headers):
        next_start = headers[pos + 1].start if pos + 1 < len(headers) else len(lines)
        body_lines = trim_trailing_blanks(lines[header.header_end:next_start])
        entries[header.term] = GlossaryStaticEntry(term=header.term, body_lines=body_lines)
    return entries


def parse_entry_header(lines: list[str], index: int) -> EntryHeader | None:
    line = lines[index]
    if not line.startswith(".. _fls_"):
        return None

    cursor = index + 1
    while cursor < len(lines) and lines[cursor].strip() == "":
        cursor += 1
    if cursor + 1 >= len(lines):
        return None

    title = lines[cursor]
    underline = lines[cursor + 1]
    if not is_caret_underline(underline):
        return None

    header_end = cursor + 2
    if header_end < len(lines) and lines[header_end].strip() == "":
        header_end += 1

    return EntryHeader(start=index, term=title.strip(), header_end=header_end)


def is_caret_underline(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and set(stripped) == {"^"}


def trim_trailing_blanks(lines: list[str]) -> list[str]:
    trimmed = list(lines)
    while trimmed and trimmed[-1].strip() == "":
        trimmed.pop()
    return trimmed


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


if __name__ == "__main__":
    raise SystemExit(main())

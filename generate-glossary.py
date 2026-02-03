#!/usr/bin/env -S uv run
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys


DIRECTIVE_RE = re.compile(r"^(?P<indent>\s*)\.\.\s+glossary-entry::\s*(?P<term>.+?)\s*$")


@dataclass
class GlossaryEntry:
    term: str
    kind: str
    propagate: bool
    glossary_lines: list[str] | None
    chapter_lines: list[str] | None
    source: str
    line: int


@dataclass
class StaticSegment:
    term: str | None
    lines: list[str]
    header_end: int | None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", default="src", help="Source directory")
    parser.add_argument(
        "--static",
        default="src/glossary.static.rst.inc",
        help="Static glossary file",
    )
    parser.add_argument(
        "--output",
        default="build/generated.glossary.rst",
        help="Generated glossary output file",
    )
    parser.add_argument(
        "--update-static",
        action="store_true",
        help="Overwrite the static glossary with generated output",
    )
    args = parser.parse_args()

    src_dir = Path(args.src)
    static_path = Path(args.static)
    output_path = Path(args.output)

    if not static_path.is_file():
        print(f"error: missing static glossary at {static_path}", file=sys.stderr)
        return 1

    entries = collect_glossary_entries(src_dir)
    static_lines, static_has_newline = read_lines(static_path)
    segments = parse_static_segments(static_lines)
    output_lines = render_glossary(segments, entries)

    write_lines(output_path, output_lines, static_has_newline)

    if args.update_static:
        write_lines(static_path, output_lines, static_has_newline)

    return 0


def collect_glossary_entries(src_dir: Path) -> dict[str, GlossaryEntry]:
    entries: dict[str, GlossaryEntry] = {}
    for path in sorted(src_dir.glob("*.rst")):
        file_entries = parse_glossary_entries(path)
        for entry in file_entries:
            if entry.term in entries:
                warn(
                    entry.source,
                    entry.line,
                    f"duplicate glossary-entry for {entry.term}",
                )
                continue
            entries[entry.term] = entry
    return entries


def parse_glossary_entries(path: Path) -> list[GlossaryEntry]:
    lines, _ = read_lines(path)
    results: list[GlossaryEntry] = []
    index = 0
    while index < len(lines):
        match = DIRECTIVE_RE.match(lines[index])
        if not match:
            index += 1
            continue

        base_indent = len(match.group("indent"))
        term = match.group("term").strip()
        block_lines, next_index = read_indented_block(lines, index + 1, base_indent)
        options, content_lines = split_options(block_lines)
        glossary_lines, chapter_lines = parse_section_blocks(
            content_lines, str(path), index + 1
        )

        kind = options.get("kind", "term")
        propagate = options.get("propagate", False)

        if glossary_lines is None and chapter_lines is None:
            warn(str(path), index + 1, "glossary-entry requires :glossary: or :chapter:")
            index = max(next_index, index + 1)
            continue

        results.append(
            GlossaryEntry(
                term=term,
                kind=kind,
                propagate=propagate,
                glossary_lines=glossary_lines,
                chapter_lines=chapter_lines,
                source=str(path),
                line=index + 1,
            )
        )

        index = max(next_index, index + 1)

    return results


def read_indented_block(
    lines: list[str], start_index: int, base_indent: int
) -> tuple[list[str], int]:
    index = start_index
    block_indent = None

    while index < len(lines):
        line = lines[index]
        if line.strip() == "":
            if count_indent(line) <= base_indent:
                return [], index
            index += 1
            continue

        indent = count_indent(line)
        if indent <= base_indent:
            return [], index
        block_indent = indent
        break

    if block_indent is None:
        return [], index

    block_lines: list[str] = []
    while index < len(lines):
        line = lines[index]
        if line.strip() == "":
            if count_indent(line) <= base_indent:
                break
            block_lines.append("")
            index += 1
            continue

        indent = count_indent(line)
        if indent < block_indent:
            break

        block_lines.append(line[block_indent:])
        index += 1

    return block_lines, index


def split_options(block_lines: list[str]) -> tuple[dict[str, object], list[str]]:
    options: dict[str, object] = {}
    content: list[str] = []
    in_options = True

    for line in block_lines:
        if in_options:
            if line.strip() == "":
                in_options = False
                continue

            if line.startswith(":") and ":" in line[1:]:
                name, value = parse_option_line(line)
                if name in ("kind", "propagate"):
                    options[name] = parse_option_value(name, value)
                    continue

            in_options = False

        content.append(line)

    return options, content


def parse_option_line(line: str) -> tuple[str, str]:
    parts = line.split(":", 2)
    name = parts[1].strip() if len(parts) > 1 else ""
    value = parts[2].strip() if len(parts) > 2 else ""
    return name, value


def parse_option_value(name: str, value: str) -> object:
    if name == "propagate":
        normalized = value.strip().lower()
        if normalized in ("true", "false"):
            return normalized == "true"
        return False
    return value


def parse_section_blocks(
    content_lines: list[str], source: str, start_line: int
) -> tuple[list[str] | None, list[str] | None]:
    sections = {"glossary": None, "chapter": None}
    current = None
    buffer: list[str] = []

    for offset, line in enumerate(content_lines):
        stripped = line.strip()
        if stripped in (":glossary:", ":chapter:") and line.startswith(":"):
            if current is not None:
                sections[current] = dedent_block(buffer)
            current = stripped.strip(":")
            if sections[current] is not None:
                warn(source, start_line + offset, f"duplicate :{current}: block")
            buffer = []
            continue

        if current is None:
            if stripped:
                warn(
                    source,
                    start_line + offset,
                    "glossary-entry content must be inside :glossary: or :chapter:",
                )
            continue

        buffer.append(line)

    if current is not None:
        sections[current] = dedent_block(buffer)

    sections["glossary"] = normalize_block(
        sections["glossary"], source, start_line, "glossary"
    )
    sections["chapter"] = normalize_block(
        sections["chapter"], source, start_line, "chapter"
    )

    return sections["glossary"], sections["chapter"]


def normalize_block(
    block_lines: list[str] | None, source: str, line: int, name: str
) -> list[str] | None:
    if block_lines is None:
        return None
    if not any(content.strip() for content in block_lines):
        warn(source, line, f":{name}: block is empty")
        return None
    return block_lines


def parse_static_segments(lines: list[str]) -> list[StaticSegment]:
    entry_headers = []
    for index in range(len(lines)):
        header = parse_entry_header(lines, index)
        if header is not None:
            entry_headers.append(header)

    if not entry_headers:
        return [StaticSegment(term=None, lines=lines, header_end=None)]

    segments: list[StaticSegment] = []
    cursor = 0
    for pos, header in enumerate(entry_headers):
        if header.start > cursor:
            segments.append(
                StaticSegment(term=None, lines=lines[cursor : header.start], header_end=None)
            )

        next_start = entry_headers[pos + 1].start if pos + 1 < len(entry_headers) else len(lines)
        entry_lines = lines[header.start:next_start]
        segments.append(
            StaticSegment(
                term=header.term,
                lines=entry_lines,
                header_end=header.header_end - header.start,
            )
        )
        cursor = next_start

    if cursor < len(lines):
        segments.append(StaticSegment(term=None, lines=lines[cursor:], header_end=None))

    return segments


@dataclass
class EntryHeader:
    start: int
    term: str
    header_end: int


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


def render_glossary(
    segments: list[StaticSegment], entries: dict[str, GlossaryEntry]
) -> list[str]:
    output: list[str] = []
    used_terms: set[str] = set()

    for segment in segments:
        if segment.term is None:
            output.extend(segment.lines)
            continue

        entry = entries.get(segment.term)
        if entry is None:
            output.extend(segment.lines)
            continue

        block = select_glossary_block(entry)
        if block is None:
            output.extend(segment.lines)
            continue

        used_terms.add(segment.term)

        header_end = segment.header_end or 0
        header_lines = ensure_header_blank_line(segment.lines[:header_end])
        body_lines = segment.lines[header_end:]
        _, trailing_blanks = split_trailing_blanks(body_lines)
        new_body, _ = split_trailing_blanks(block)

        output.extend(header_lines)
        output.extend(new_body)
        output.extend(trailing_blanks)

    for term, entry in entries.items():
        if term not in used_terms:
            warn(entry.source, entry.line, f"glossary-entry term not found in static glossary: {term}")

    return output


def select_glossary_block(entry: GlossaryEntry) -> list[str] | None:
    if entry.glossary_lines is not None:
        return entry.glossary_lines
    if entry.chapter_lines is not None and entry.propagate:
        return entry.chapter_lines
    if entry.chapter_lines is not None and not entry.propagate:
        warn(entry.source, entry.line, f"glossary-entry for {entry.term} not exported")
    return None


def split_trailing_blanks(lines: list[str]) -> tuple[list[str], list[str]]:
    trimmed = list(lines)
    trailing: list[str] = []
    while trimmed and trimmed[-1].strip() == "":
        trailing.insert(0, trimmed.pop())
    return trimmed, trailing


def ensure_header_blank_line(lines: list[str]) -> list[str]:
    if not lines:
        return [""]
    if lines[-1].strip() != "":
        return [*lines, ""]
    return list(lines)


def dedent_block(lines: list[str]) -> list[str]:
    indents = [len(line) - len(line.lstrip(" ")) for line in lines if line.strip()]
    indent = min(indents) if indents else 0
    return [line[indent:] if len(line) >= indent else "" for line in lines]


def count_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def read_lines(path: Path) -> tuple[list[str], bool]:
    data = path.read_text(encoding="utf-8")
    return data.splitlines(), data.endswith("\n")


def write_lines(path: Path, lines: list[str], trailing_newline: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines)
    if trailing_newline:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def warn(source: str, line: int, message: str) -> None:
    print(f"warning: {source}:{line}: {message}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())

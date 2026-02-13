#!/usr/bin/env -S uv run
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import difflib
from io import StringIO
import json
from pathlib import Path
import re
import subprocess
import sys

from sphinx.application import Sphinx

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
GLOSSARY_PATH = SRC_DIR / "glossary.rst"
GLOSSARY_DOC = "glossary"
EXCLUDED_CHAPTER_DOCS = {"glossary.rst", "index.rst", "changelog.rst"}

DT_RE = re.compile(r":dt:`([^`]+)`")
DC_RE = re.compile(r":dc:`([^`]+)`")
DP_LINE_RE = re.compile(r"^:dp:`[^`]+`\s*$")
ROLE_WITH_TARGET_RE = re.compile(r":[a-z]+:`([^`<]+)<[^`>]+>`")
ROLE_RE = re.compile(r":[a-z]+:`([^`]+)`")
FOR_SEE_RE = re.compile(r"^For\b.*\bsee\b", flags=re.IGNORECASE)


def load_ferrocene_modules():
    exts_path = str(ROOT / "exts")
    if exts_path not in sys.path:
        sys.path.append(exts_path)

    from ferrocene_spec.definitions import (  # pylint: disable=import-outside-toplevel
        DefIdNode,
        id_from_text,
        parse_target_from_text,
    )
    from ferrocene_spec_lints import (  # pylint: disable=import-outside-toplevel
        glossary_migration,
    )

    return DefIdNode, id_from_text, parse_target_from_text, glossary_migration


DefIdNode, id_from_text, parse_target_from_text, glossary_migration = (
    load_ferrocene_modules()
)


@dataclass
class DefinitionRecord:
    term: str
    term_id: str
    file: str
    line: int
    paragraph: str


@dataclass
class CheckResult:
    name: str
    passed: bool
    details: dict


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def collapse_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def strip_dp_line(text: str) -> str:
    lines = text.splitlines()
    if lines and DP_LINE_RE.match(lines[0].strip()):
        lines = lines[1:]
    return "\n".join(lines).strip()


def normalize_for_compare(text: str) -> str:
    return collapse_whitespace(strip_dp_line(text))


def strip_roles(text: str) -> str:
    with_targets = ROLE_WITH_TARGET_RE.sub(lambda match: match.group(1).strip(), text)
    without_targets = ROLE_RE.sub(lambda match: match.group(1).strip(), with_targets)
    return collapse_whitespace(without_targets)


def paragraph_bounds(lines: list[str], index: int) -> tuple[int, int]:
    start = index
    while start > 0 and lines[start - 1].strip() != "":
        start -= 1

    end = index
    while end + 1 < len(lines) and lines[end + 1].strip() != "":
        end += 1

    return start, end


def extract_definitions(
    path: Path, *, include_code_terms: bool
) -> dict[str, list[DefinitionRecord]]:
    lines = read_lines(path)
    definitions: dict[str, list[DefinitionRecord]] = {}

    for index, line in enumerate(lines):
        if ":dt:`" not in line and (not include_code_terms or ":dc:`" not in line):
            continue

        matches = [match.group(1).strip() for match in DT_RE.finditer(line)]
        if include_code_terms:
            matches.extend(match.group(1).strip() for match in DC_RE.finditer(line))
        if not matches:
            continue

        start, end = paragraph_bounds(lines, index)
        paragraph = "\n".join(lines[start : end + 1]).strip()
        record_line = index + 1

        for raw_term in matches:
            term, target = parse_target_from_text(raw_term)
            term_id = id_from_text("term", target)
            record = DefinitionRecord(
                term=term,
                term_id=term_id,
                file=path.relative_to(ROOT).as_posix(),
                line=record_line,
                paragraph=paragraph,
            )
            definitions.setdefault(term_id, []).append(record)

    return definitions


def collect_glossary_terms() -> list[dict]:
    lines = read_lines(GLOSSARY_PATH)
    headings: list[tuple[str, int]] = []

    for index in range(len(lines) - 1):
        title = lines[index].strip()
        underline = lines[index + 1].strip()

        if not title or title == "Glossary" or title.startswith(".."):
            continue
        if not underline or set(underline) != {"^"}:
            continue
        if len(underline) < len(title):
            continue

        headings.append((title, index))

    terms: list[dict] = []
    seen_term_ids: set[str] = set()
    for heading_index, (title, line_index) in enumerate(headings):
        next_line_index = (
            headings[heading_index + 1][1]
            if heading_index + 1 < len(headings)
            else len(lines)
        )
        section_candidates: list[tuple[str, str, int]] = []

        for section_line_index in range(line_index, next_line_index):
            line = lines[section_line_index]
            for match in DT_RE.finditer(line):
                raw_term = match.group(1).strip()
                term, target = parse_target_from_text(raw_term)
                section_candidates.append(
                    (term, id_from_text("term", target), section_line_index + 1)
                )
            for match in DC_RE.finditer(line):
                raw_term = match.group(1).strip()
                term, target = parse_target_from_text(raw_term)
                section_candidates.append(
                    (term, id_from_text("term", target), section_line_index + 1)
                )

        if not section_candidates:
            heading_term, heading_target = parse_target_from_text(title)
            section_candidates.append(
                (heading_term, id_from_text("term", heading_target), line_index + 1)
            )

        for term, term_id, term_line in section_candidates:
            if term_id in seen_term_ids:
                continue
            seen_term_ids.add(term_id)
            terms.append(
                {
                    "term": term,
                    "term_id": term_id,
                    "line": term_line,
                }
            )

    return terms


def collect_glossary_definitions() -> dict[str, list[DefinitionRecord]]:
    return extract_definitions(GLOSSARY_PATH, include_code_terms=False)


def collect_chapter_definitions() -> dict[str, list[DefinitionRecord]]:
    aggregated: dict[str, list[DefinitionRecord]] = {}
    for path in sorted(SRC_DIR.glob("*.rst")):
        if path.name in EXCLUDED_CHAPTER_DOCS:
            continue
        file_definitions = extract_definitions(path, include_code_terms=True)
        for term_id, records in file_definitions.items():
            aggregated.setdefault(term_id, []).extend(records)
    return aggregated


def build_term_inventory(glossary_terms, chapter_definitions):
    inventory = []
    missing = []

    for item in glossary_terms:
        chapter_records = chapter_definitions.get(item["term_id"], [])
        chosen = chapter_records[0] if chapter_records else None
        entry = {
            "term": item["term"],
            "term_id": item["term_id"],
            "glossary_line": item["line"],
            "chapter_file": chosen.file if chosen else None,
            "chapter_line": chosen.line if chosen else None,
        }
        inventory.append(entry)
        if chosen is None:
            missing.append(entry)

    return inventory, missing


def classify_mismatch(glossary_text: str, chapter_text: str) -> str:
    glossary_plain = strip_roles(glossary_text)
    chapter_plain = strip_roles(chapter_text)

    if glossary_plain == chapter_plain:
        return "role-only"

    if not glossary_plain or not chapter_plain:
        return "structural"

    if glossary_plain in chapter_plain or chapter_plain in glossary_plain:
        return "scope"

    return "wording"


def compare_definitions(glossary_definitions, chapter_definitions):
    mismatches = []

    for term_id, glossary_records in sorted(glossary_definitions.items()):
        chapter_records = chapter_definitions.get(term_id)
        if not chapter_records:
            continue

        glossary_record = glossary_records[0]
        chapter_record = chapter_records[0]
        glossary_text = normalize_for_compare(glossary_record.paragraph)

        if is_redundant_see_paragraph(glossary_text):
            continue

        chapter_text = normalize_for_compare(chapter_record.paragraph)

        if glossary_text == chapter_text:
            continue

        classification = classify_mismatch(glossary_text, chapter_text)
        if classification == "role-only":
            continue

        mismatches.append(
            {
                "term": glossary_record.term,
                "term_id": term_id,
                "classification": classification,
                "glossary": asdict(glossary_record),
                "chapter": asdict(chapter_record),
                "glossary_normalized": glossary_text,
                "chapter_normalized": chapter_text,
            }
        )

    return mismatches


def collect_glossary_paragraphs() -> list[dict]:
    lines = read_lines(GLOSSARY_PATH)
    paragraphs = []

    index = 0
    while index < len(lines):
        if not lines[index].strip().startswith(":dp:`"):
            index += 1
            continue

        paragraph_line = index + 1
        dp_line = lines[index].strip()
        index += 1

        text_lines = []
        while index < len(lines) and lines[index].strip() != "":
            text_lines.append(lines[index].strip())
            index += 1

        paragraph_text = collapse_whitespace(" ".join(text_lines))
        paragraphs.append(
            {
                "line": paragraph_line,
                "dp": dp_line,
                "text": paragraph_text,
            }
        )

    return paragraphs


def is_redundant_see_paragraph(text: str) -> bool:
    if not text:
        return False
    if text.startswith("See "):
        return True
    if FOR_SEE_RE.match(text):
        return True
    return False


def build_sphinx_app() -> Sphinx:
    build_dir = ROOT / "build" / "glossary-migration-check"
    out_dir = build_dir / "out"
    doctree_dir = build_dir / "doctrees"
    out_dir.mkdir(parents=True, exist_ok=True)
    doctree_dir.mkdir(parents=True, exist_ok=True)

    app = Sphinx(
        srcdir=str(SRC_DIR),
        confdir=str(SRC_DIR),
        outdir=str(out_dir),
        doctreedir=str(doctree_dir),
        buildername="dummy",
        status=StringIO(),
        warning=StringIO(),
        freshenv=True,
        warningiserror=False,
    )
    app.build(force_all=True)
    return app


def run_generator_parity() -> tuple[bool, dict]:
    script = ROOT / "generate-glossary.py"
    generated = ROOT / "build" / "generated.glossary.rst"
    committed = ROOT / "src" / "glossary.rst.inc"

    if not script.is_file():
        return False, {"error": "generate-glossary.py is missing"}

    result = subprocess.run(
        ["./generate-glossary.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return False, {
            "error": "generator command failed",
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    if not generated.is_file() or not committed.is_file():
        return False, {
            "error": "generated or committed glossary artifact is missing",
            "generated": generated.as_posix(),
            "committed": committed.as_posix(),
        }

    generated_text = generated.read_text(encoding="utf-8").splitlines(keepends=True)
    committed_text = committed.read_text(encoding="utf-8").splitlines(keepends=True)
    if generated_text == committed_text:
        return True, {
            "generated": generated.as_posix(),
            "committed": committed.as_posix(),
        }

    diff = list(
        difflib.unified_diff(
            committed_text,
            generated_text,
            fromfile="src/glossary.rst.inc",
            tofile="build/generated.glossary.rst",
            n=3,
        )
    )
    return False, {
        "error": "parity mismatch",
        "generated": generated.as_posix(),
        "committed": committed.as_posix(),
        "diff_preview": "".join(diff[:200]),
    }


def add_result(results: list[CheckResult], name: str, passed: bool, details=None):
    results.append(CheckResult(name=name, passed=passed, details=details or {}))


def write_phase_artifact(report_path: Path | None, name: str, data):
    if report_path is None:
        return None
    artifact_path = report_path.parent / name
    write_json(artifact_path, data)
    return artifact_path.as_posix()


def run_checks(phase: int, strict: bool, report_path: Path | None) -> int:
    glossary_terms = collect_glossary_terms()
    glossary_definitions = collect_glossary_definitions()
    chapter_definitions = collect_chapter_definitions()

    artifacts = {}
    results: list[CheckResult] = []

    inventory, missing = build_term_inventory(glossary_terms, chapter_definitions)
    artifacts["term_inventory"] = write_phase_artifact(
        report_path, "term-inventory.json", inventory
    )
    artifacts["missing_terms"] = write_phase_artifact(
        report_path, "missing-terms.json", missing
    )
    add_result(
        results,
        "glossary-terms-covered-by-chapters",
        len(missing) == 0,
        {"missing_count": len(missing)},
    )

    if phase >= 2:
        mismatches = compare_definitions(glossary_definitions, chapter_definitions)
        artifacts["mismatch_report"] = write_phase_artifact(
            report_path, "mismatch-report.json", mismatches
        )
        add_result(
            results,
            "glossary-chapter-definition-match",
            len(mismatches) == 0,
            {"mismatch_count": len(mismatches)},
        )

    app = None
    if phase >= 3:
        glossary_dt_lines = glossary_migration.find_glossary_dt_lines(ROOT)
        add_result(
            results,
            "no-dt-in-glossary-source",
            len(glossary_dt_lines) == 0,
            {
                "violations": [
                    {
                        "file": violation["file"].relative_to(ROOT).as_posix(),
                        "line": violation["line"],
                    }
                    for violation in glossary_dt_lines
                ]
            },
        )

        app = build_sphinx_app()
        glossary_doctree = app.env.get_doctree(GLOSSARY_DOC)
        term_nodes = [
            node
            for node in glossary_doctree.findall(DefIdNode)
            if node.get("def_kind") == "term"
        ]
        add_result(
            results,
            "no-term-definitions-in-glossary-doctree",
            len(term_nodes) == 0,
            {
                "count": len(term_nodes),
                "sample": [
                    {
                        "text": node.get("def_text"),
                        "line": node.line,
                    }
                    for node in term_nodes[:20]
                ],
            },
        )

        term_storage = getattr(app.env, "spec_items_term", {})
        validation = []
        glossary_owned = []
        unresolved = []
        for item in glossary_terms:
            term_id = item["term_id"]
            target = term_storage.get(term_id)
            target_doc = target.document if target else None
            target_anchor = f"term_{term_id}"
            validation.append(
                {
                    "term": item["term"],
                    "term_id": term_id,
                    "target_doc": target_doc,
                    "target_anchor": target_anchor,
                }
            )

            if target is None:
                unresolved.append(item["term"])
            elif target.document == GLOSSARY_DOC:
                glossary_owned.append(item["term"])

        artifacts["term_target_validation"] = write_phase_artifact(
            report_path, "term-target-validation.json", validation
        )
        add_result(
            results,
            "canonical-term-targets-non-glossary",
            len(glossary_owned) == 0 and len(unresolved) == 0,
            {
                "glossary_owned": glossary_owned,
                "unresolved": unresolved,
            },
        )

    if phase >= 4:
        paragraphs = collect_glossary_paragraphs()
        redundant = [
            paragraph
            for paragraph in paragraphs
            if is_redundant_see_paragraph(paragraph["text"])
        ]
        ledger = {
            "redundant": redundant,
            "retained_count": len(paragraphs) - len(redundant),
        }
        artifacts["removed_retained_ledger"] = write_phase_artifact(
            report_path, "removed-retained-ledger.json", ledger
        )
        add_result(
            results,
            "no-redundant-see-paragraphs",
            len(redundant) == 0,
            {"redundant_count": len(redundant)},
        )

    if phase >= 5:
        parity_ok, parity_details = run_generator_parity()
        add_result(results, "generated-glossary-parity", parity_ok, parity_details)

    serialized_results = [
        {
            "name": result.name,
            "passed": result.passed,
            "details": result.details,
        }
        for result in results
    ]

    if report_path is not None:
        write_json(
            report_path,
            {
                "phase": phase,
                "strict": strict,
                "checks": serialized_results,
                "artifacts": artifacts,
            },
        )

    failed = [result for result in results if not result.passed]
    for result in results:
        marker = "PASS" if result.passed else "FAIL"
        print(f"[{marker}] {result.name}")

    if strict and failed:
        print(f"strict checks failed: {len(failed)}", file=sys.stderr)
        return 1

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", type=int, required=True, choices=[1, 2, 3, 4, 5])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report_path = args.report.resolve() if args.report else None
    return run_checks(args.phase, args.strict, report_path)


if __name__ == "__main__":
    raise SystemExit(main())

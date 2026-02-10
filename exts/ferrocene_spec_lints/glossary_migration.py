# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from __future__ import annotations

from pathlib import Path
import re


DISALLOWED_DIRECTIVES = (".. glossary-entry::", ".. glossary-include::")
GLOSSARY_DOC = "glossary.rst"
DT_ROLE_RE = re.compile(r":dt:`")


def iter_rst_files(root: Path):
    src = root / "src"
    for path in sorted(src.glob("*.rst")):
        yield path


def find_disallowed_directives(root: Path):
    violations = []
    for path in iter_rst_files(root):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            for directive in DISALLOWED_DIRECTIVES:
                if stripped.startswith(directive):
                    violations.append(
                        {
                            "file": path,
                            "line": index,
                            "directive": directive,
                            "text": stripped,
                        }
                    )
    return violations


def find_glossary_dt_lines(root: Path):
    glossary = root / "src" / GLOSSARY_DOC
    if not glossary.is_file():
        return []

    violations = []
    lines = glossary.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines, start=1):
        if DT_ROLE_RE.search(line):
            violations.append({"file": glossary, "line": index, "text": line.rstrip()})
    return violations


def check(app, raise_error):
    phase = app.config.lint_glossary_migration_phase
    strict = app.config.lint_glossary_migration_strict
    if phase <= 0 or not strict:
        return

    root = Path(app.confdir).resolve().parent

    for violation in find_disallowed_directives(root):
        raise_error(
            f"disallowed directive '{violation['directive']}' in {violation['file']}:{violation['line']}"
        )

    if phase >= 3:
        for violation in find_glossary_dt_lines(root):
            raise_error(
                f":dt: role remains in glossary source at {violation['file']}:{violation['line']}"
            )

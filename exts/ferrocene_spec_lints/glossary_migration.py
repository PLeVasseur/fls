# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from __future__ import annotations

import re
from pathlib import Path

GLOSSARY_DOC = "glossary.rst"
DT_ROLE_RE = re.compile(r":dt:`")


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

    if phase >= 3:
        for violation in find_glossary_dt_lines(root):
            location = f"{violation['file']}:{violation['line']}"
            raise_error(f":dt: role remains in glossary source at {location}")

# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

import sphinx
import typing
from . import alphabetical_section_titles, glossary_migration, require_paragraph_ids


def run_lints(app, env):
    alphabetical_section_titles.check(app, raise_error)
    require_paragraph_ids.check(app, raise_error)
    glossary_migration.check(app, raise_error)


def raise_error(message, *, location=None):
    logger = sphinx.util.logging.getLogger(__name__)
    logger.warning(message, location=location)


def setup(app):
    app.connect("env-check-consistency", run_lints)

    app.add_config_value("lint_alphabetical_section_titles", [], "", typing.List[str])
    app.add_config_value("lint_no_paragraph_ids", [], "", typing.List[str])
    app.add_config_value("lint_glossary_migration_phase", 0, "", int)
    app.add_config_value("lint_glossary_migration_strict", False, "", bool)
    app.add_config_value("lint_glossary_migration_report", "", "", str)
    app.add_config_value("lint_glossary_migration_report_root", "", "", str)

    return {
        "version": "0",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }

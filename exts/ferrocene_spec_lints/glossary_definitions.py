# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from ferrocene_spec import glossary


def check(app, raise_error):
    check_duplicate_definitions(app, raise_error)


def check_duplicate_definitions(app, raise_error):
    for (def_kind, term_id), defs in glossary.get_storage(app.env).items():
        if len(defs) <= 1:
            continue

        documents = sorted({definition.document for definition in defs})
        if len(documents) == 1:
            raise_error(
                f"{def_kind} '{term_id}' is defined multiple times in {documents[0]}"
            )
        else:
            raise_error(
                f"{def_kind} '{term_id}' is defined in multiple documents: {', '.join(documents)}"
            )

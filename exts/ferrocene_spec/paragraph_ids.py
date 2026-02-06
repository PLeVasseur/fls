# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from . import definitions, informational, utils
from collections import defaultdict
from docutils import nodes
from sphinx.environment.collectors import EnvironmentCollector
import hashlib
import json
import os
import sphinx


ROLE_KIND_TO_NAME = {
    ("term", "definition"): "dt",
    ("term", "reference"): "t",
    ("syntaxes", "definition"): "ds",
    ("syntaxes", "reference"): "s",
}


def normalize_text(value):
    return " ".join(value.split())


def hash_values(values):
    sha256 = hashlib.sha256()
    for value in values:
        sha256.update(value.encode("utf-8"))
        sha256.update(b"\x00")
    return sha256.hexdigest()


def markup_tokens(node):
    if isinstance(node, nodes.Text):
        text = normalize_text(str(node))
        if text:
            return [f"text:{text}"]
        return []

    if not isinstance(node, nodes.Element):
        return []

    classes = ",".join(sorted(node.get("classes", [])))
    token = f"node:{node.__class__.__name__}:{classes}"

    if isinstance(node, nodes.reference):
        token += f":{node.get('refuri', '')}:{node.get('refid', '')}"

    result = [token]
    for child in node.children:
        result.extend(markup_tokens(child))
    result.append(f"end:{node.__class__.__name__}")
    return result


def paragraph_id_for_paragraph_node(paragraph):
    for node in paragraph.findall(definitions.DefIdNode):
        if node.get("def_kind") == definitions.paragraphs.NAME:
            return node.get("def_id")

    for node in paragraph.findall(nodes.inline):
        if "spec-paragraph-id" in node.get("classes", []):
            ids = node.get("ids", [])
            if ids:
                return ids[0]
    return None


def list_structure_for_paragraph(paragraph):
    depth = 0
    ordered = False
    item_count = 0

    cursor = paragraph.parent
    while cursor is not None:
        if isinstance(cursor, nodes.bullet_list):
            depth += 1
            if item_count == 0:
                ordered = False
                item_count = len(list(cursor.findall(nodes.list_item)))
        elif isinstance(cursor, nodes.enumerated_list):
            depth += 1
            if item_count == 0:
                ordered = True
                item_count = len(list(cursor.findall(nodes.list_item)))
        cursor = cursor.parent

    return {
        "depth": depth,
        "item_count": item_count,
        "ordered": ordered,
    }


def extract_doctree_metadata(env):
    metadata = {}
    std_docs_prefix = f"{env.config.spec_std_docs_url}/?search="

    for docname in env.found_docs:
        doctree = env.get_doctree(docname)
        for paragraph in doctree.findall(nodes.paragraph):
            paragraph_id = paragraph_id_for_paragraph_node(paragraph)
            if paragraph_id is None:
                continue

            inline_literals = []
            literal_blocks = []
            std_role_count = 0

            for literal in paragraph.findall(nodes.literal):
                if isinstance(literal.parent, nodes.literal_block):
                    continue
                inline_literals.append(normalize_text(literal.astext()))

            for literal_block in paragraph.findall(nodes.literal_block):
                literal_blocks.append(normalize_text(literal_block.astext()))

            for ref in paragraph.findall(nodes.reference):
                if str(ref.get("refuri", "")).startswith(std_docs_prefix):
                    std_role_count += 1

            metadata[paragraph_id] = {
                "markup_checksum": hash_values(markup_tokens(paragraph)),
                "literal_inventory": {
                    "inline_count": len(inline_literals),
                    "inline_hash": hash_values(inline_literals),
                    "block_count": len(literal_blocks),
                    "block_hash": hash_values(literal_blocks),
                },
                "list_structure": list_structure_for_paragraph(paragraph),
                "std_role_count": std_role_count,
            }

    return metadata


def write_paragraph_ids(app):
    env = app.env
    informational_storage = informational.get_storage(env)
    definition_locations = getattr(env, "spec_definition_locations", {})

    paragraph_items = definitions.get_storage(env, definitions.paragraphs)
    paragraphs_by_section = defaultdict(list)
    paragraphs_by_id = {}
    for paragraph in paragraph_items.values():
        paragraph_link = app.builder.get_target_uri(paragraph.document) + "#" + paragraph.id
        paragraph_data = {
            "id": paragraph.id,
            "number": paragraph.number(app.env),
            "link": paragraph_link,
            "checksum": paragraph.content_checksum(),
            "plaintext": paragraph.plaintext,
            "document": paragraph.document,
            "section_id": paragraph.section_id,
            "markup_checksum": paragraph.content_checksum(),
            "role_inventory": {"dt": 0, "t": 0, "ds": 0, "s": 0, "std": 0},
            "literal_inventory": {
                "inline_count": 0,
                "inline_hash": hash_values([]),
                "block_count": 0,
                "block_hash": hash_values([]),
            },
            "list_structure": {
                "depth": 0,
                "item_count": 0,
                "ordered": False,
            },
        }
        paragraphs_by_section[paragraph.section_id].append(paragraph_data)
        paragraphs_by_id[paragraph.id] = paragraph_data

    role_inventory_by_paragraph = {
        paragraph_id: {"dt": 0, "t": 0, "ds": 0, "s": 0, "std": 0}
        for paragraph_id in paragraphs_by_id
    }

    references = []
    for docname, records in definition_locations.items():
        for record in records:
            paragraph_id = record["paragraph_id"]
            role_name = ROLE_KIND_TO_NAME.get((record["kind"], record["type"]))
            if role_name is not None and paragraph_id in role_inventory_by_paragraph:
                role_inventory_by_paragraph[paragraph_id][role_name] += 1

            references.append(
                {
                    "document": docname,
                    "paragraph_id": paragraph_id,
                    **record,
                }
            )

    extra_metadata = extract_doctree_metadata(env)
    for paragraph_id, metadata in extra_metadata.items():
        if paragraph_id not in paragraphs_by_id:
            continue
        role_inventory_by_paragraph[paragraph_id]["std"] += metadata["std_role_count"]
        paragraphs_by_id[paragraph_id].update(
            {
                "markup_checksum": metadata["markup_checksum"],
                "literal_inventory": metadata["literal_inventory"],
                "list_structure": metadata["list_structure"],
            }
        )

    for paragraph_id, role_inventory in role_inventory_by_paragraph.items():
        if paragraph_id in paragraphs_by_id:
            paragraphs_by_id[paragraph_id]["role_inventory"] = role_inventory

    sections_by_document = defaultdict(list)
    for section in env.spec_sections:
        sections_by_document[section.document].append(
            {
                "id": section.id,
                "number": ".".join(
                    str(n) for n in env.toc_secnumbers[section.document][section.anchor]
                ),
                "title": section.title,
                "link": app.builder.get_target_uri(section.document) + section.anchor,
                "paragraphs": paragraphs_by_section[section.id],
                "informational": (
                    section.anchor in informational_storage[section.document]
                ),
            }
        )

    documents = []
    for docname, title in env.titles.items():
        documents.append(
            {
                "title": title.astext(),
                "link": app.builder.get_target_uri(docname),
                "sections": sections_by_document[docname],
                "informational": (
                    informational.WHOLE_PAGE in informational_storage[docname]
                ),
            }
        )

    with open(os.path.join(app.outdir, "paragraph-ids.json"), "w") as f:
        json.dump({"documents": documents}, f)
        f.write("\n")

    definitions_payload = {
        "paragraph": sorted(
            [
                {
                    "id": item.id,
                    "document": item.document,
                    "anchor": item.anchor(),
                }
                for item in definitions.get_storage(env, definitions.paragraphs).values()
            ],
            key=lambda item: item["id"],
        ),
        "term": sorted(
            [
                {
                    "id": item.id,
                    "document": item.document,
                    "anchor": item.anchor(),
                }
                for item in definitions.get_storage(env, definitions.terms).values()
            ],
            key=lambda item: item["id"],
        ),
        "syntax": sorted(
            [
                {
                    "id": item.id,
                    "document": item.document,
                    "anchor": item.anchor(),
                }
                for item in definitions.get_storage(env, definitions.syntax).values()
            ],
            key=lambda item: item["id"],
        ),
        "code_term": sorted(
            [
                {
                    "id": item.id,
                    "document": item.document,
                    "anchor": item.anchor(),
                }
                for item in definitions.get_storage(env, definitions.code_terms).values()
            ],
            key=lambda item: item["id"],
        ),
    }

    with open(os.path.join(app.outdir, "paragraph-ids-rich.json"), "w") as f:
        json.dump(
            {
                "documents": documents,
                "sections": [
                    {
                        "id": section.id,
                        "document": section.document,
                        "anchor": section.anchor,
                        "title": section.title,
                    }
                    for section in env.spec_sections
                ],
                "definitions": definitions_payload,
                "definition_references": references,
            },
            f,
        )
        f.write("\n")


def build_finished(app, exception):
    # The build finished hook also runs when an exception is raised.
    if exception is not None:
        return

    with sphinx.util.display.progress_message("dumping paragraph ids"):
        write_paragraph_ids(app)


def setup(app):
    app.connect("build-finished", build_finished)
    app.add_env_collector(SectionsCollector)


class SectionsCollector(EnvironmentCollector):
    def clear_doc(self, app, env, docname):
        """
        This is called by Sphinx during incremental builds, either when a
        document was removed or when the document has been changed. In the
        latter case, process_doc is called after this method.
        """
        if not hasattr(env, "spec_sections"):
            env.spec_sections = []
        env.spec_sections = [s for s in env.spec_sections if s.document != docname]

    def merge_other(self, app, env, docnames, other):
        """
        Sphinx supports parallel builds, with each process having its own
        environment instance, but once each document is processed those
        parallel environments need to be merged together. This method does it.
        """
        if not hasattr(env, "spec_sections"):
            env.spec_sections = []
        if not hasattr(other, "spec_sections"):
            return

        for section in other.spec_sections:
            if section.document not in docnames:
                continue
            env.spec_sections.append(section)

    def process_doc(self, app, doctree):
        """
        This method can expect no existing information about the same document
        being stored in the environment, as during incremental rebuilds the
        clear_doc method is called ahead of this one.
        """
        env = app.env
        if not hasattr(env, "spec_sections"):
            env.spec_sections = []

        for section in doctree.findall(nodes.section):
            try:
                id, anchor = utils.section_id_and_anchor(section)
            except utils.NoSectionIdError:
                continue

            title = None
            for child in section.children:
                if isinstance(child, nodes.title):
                    title = child.astext()
            if title is None:
                raise RuntimeError(f"section without title: {section}")

            env.spec_sections.append(
                Section(id=id, title=title, anchor=anchor, document=env.docname)
            )


class Section:
    def __init__(self, id, title, anchor, document):
        self.id = id
        self.title = title
        self.anchor = anchor
        self.document = document

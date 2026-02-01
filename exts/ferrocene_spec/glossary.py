# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from dataclasses import dataclass
import hashlib
import re
import string
from typing import Iterable, Optional

from docutils import nodes
from sphinx.directives import SphinxDirective
from sphinx.environment.collectors import EnvironmentCollector
from sphinx.transforms import SphinxTransform
import sphinx

from . import definitions, utils
from .definitions import paragraphs
from .paragraph_ids import Section

BASE62_ALPHABET = string.ascii_letters + string.digits
BASE62_BASE = len(BASE62_ALPHABET)
ID_LENGTH = 12

TERM_KIND = "term"
PARAGRAPH_KIND = "paragraph"

SPLIT_NUMBERS = re.compile(r"([0-9]+)")


class GlossaryMarkerNode(nodes.Element):
    pass


class GlossaryDirective(SphinxDirective):
    has_content = False

    def run(self):
        node = GlossaryMarkerNode()
        node["docname"] = self.env.docname
        return [node]


@dataclass(frozen=True)
class GlossaryDefinition:
    term_id: str
    display_text: str
    document: str
    line: Optional[int]


@dataclass(frozen=True)
class GlossarySectionSource:
    title: str
    title_id: str
    section_id: str
    node: nodes.section
    term_ids: tuple[str, ...]


@dataclass(frozen=True)
class GlossaryEntry:
    term_id: str
    title: str
    definition: Optional[GlossaryDefinition]
    source_section: Optional[GlossarySectionSource]


class GlossaryCollector(EnvironmentCollector):
    def clear_doc(self, app, env, docname):
        storage = get_storage(env)
        for term_id in list(storage.keys()):
            storage[term_id] = [d for d in storage[term_id] if d.document != docname]
            if not storage[term_id]:
                del storage[term_id]

    def merge_other(self, app, env, docnames, other):
        storage = get_storage(env)
        other_storage = get_storage(other)
        for term_id, defs in other_storage.items():
            for definition in defs:
                if definition.document in docnames:
                    storage.setdefault(term_id, []).append(definition)

    def process_doc(self, app, doctree):
        docname = app.env.docname
        storage = get_storage(app.env)
        for node in doctree.findall(definitions.DefIdNode):
            if node["def_kind"] != TERM_KIND:
                continue
            storage.setdefault(node["def_id"], []).append(
                GlossaryDefinition(
                    term_id=node["def_id"],
                    display_text=node["def_text"],
                    document=docname,
                    line=node.line,
                )
            )

    def get_updated_docs(self, app, env):
        signature = compute_signature(get_storage(env))
        previous = getattr(env, "spec_glossary_signature", None)
        if signature == previous:
            return []

        env.spec_glossary_signature = signature
        apply_term_precedence(env)
        if "glossary" in env.found_docs:
            return ["glossary"]
        return []


class GlossaryTransform(SphinxTransform):
    default_priority = 400

    def apply(self):
        for node in self.document.findall(GlossaryMarkerNode):
            self.replace_node(node)

    def replace_node(self, node):
        glossary_docname = node["docname"]
        source_sections = collect_glossary_source_sections(self.document)
        source_by_term_id, source_by_title_id = index_glossary_sources(source_sections)

        definitions_storage = get_storage(self.env)
        selected = select_definitions(definitions_storage, glossary_docname)

        entries = []
        used_source_sections = set()
        for definition in sort_definitions(selected):
            source = source_by_term_id.get(definition.term_id) or source_by_title_id.get(
                definition.term_id
            )
            title = source.title if source is not None else definition.display_text
            entries.append(
                GlossaryEntry(
                    term_id=definition.term_id,
                    title=title,
                    definition=definition,
                    source_section=source,
                )
            )
            if source is not None:
                used_source_sections.add(source.section_id)

        for source in source_sections:
            if source.section_id in used_source_sections:
                continue
            entries.append(
                GlossaryEntry(
                    term_id=source.title_id,
                    title=source.title,
                    definition=None,
                    source_section=source,
                )
            )

        if not entries:
            if getattr(self.env, "spec_glossary_signature", None) is not None:
                warn("no glossary definitions found", node)
            node.parent.remove(node)
            return

        used_paragraph_ids = {
            item.id
            for item in definitions.get_storage(self.env, definitions.paragraphs).values()
        }
        used_section_ids = {
            section.id for section in getattr(self.env, "spec_sections", [])
        }

        sections = []
        for entry in sort_entries(entries):
            if entry.definition is None:
                section = build_section_from_source(
                    entry,
                    glossary_docname,
                    used_paragraph_ids,
                    used_section_ids,
                )
                if section is not None:
                    sections.append(section)
                continue

            convert_term_defs = entry.definition.document != glossary_docname
            paragraph, should_warn = self.build_paragraph(
                glossary_docname,
                entry.definition,
                convert_term_defs,
            )
            if paragraph is None:
                if entry.source_section is not None:
                    section = build_section_from_source(
                        entry,
                        glossary_docname,
                        used_paragraph_ids,
                        used_section_ids,
                    )
                    if section is not None:
                        sections.append(section)
                    continue
                if should_warn:
                    warn(
                        f"missing glossary definition for '{entry.title}'",
                        node,
                    )
                continue

            paragraph_id = stable_fls_id(
                "glossary:",
                entry.term_id,
                used_paragraph_ids,
            )
            paragraph.insert(0, definitions.DefIdNode(PARAGRAPH_KIND, paragraph_id))

            if entry.source_section is not None:
                section_id = entry.source_section.section_id
                used_section_ids.add(section_id)
            else:
                section_id = stable_fls_id(
                    "glossary-section:",
                    entry.term_id,
                    used_section_ids,
                )
            section = nodes.section(ids=[section_id], names=[section_id])
            section += nodes.title("", entry.title)
            section += paragraph
            sections.append(section)

        parent = node.parent
        node.replace_self(sections)
        if parent is not None:
            for child in list(parent.children):
                if child is node:
                    continue
                if isinstance(child, nodes.section) and child not in sections:
                    parent.remove(child)

        refresh_glossary_sections(self.env, self.document, glossary_docname)
        refresh_glossary_paragraphs(self.env, self.document, glossary_docname)
        refresh_glossary_secnumbers(self.env, glossary_docname, sections)

    def build_paragraph(self, glossary_docname, definition, convert_term_defs):
        try:
            source_doctree = self.env.get_doctree(definition.document)
        except Exception:
            return None, False

        term_node = None
        for node in source_doctree.findall(definitions.DefIdNode):
            if node["def_kind"] == TERM_KIND and node["def_id"] == definition.term_id:
                term_node = node
                break

        if term_node is None:
            return None, True

        paragraph = paragraphs.find_parent_of_type(term_node, nodes.paragraph)
        if paragraph is None:
            return None, True

        paragraph = paragraph.deepcopy()

        for node in list(paragraph.findall(definitions.DefIdNode)):
            if node["def_kind"] == PARAGRAPH_KIND:
                node.replace_self([])

        if convert_term_defs:
            for node in list(paragraph.findall(definitions.DefIdNode)):
                if node["def_kind"] == TERM_KIND:
                    node.replace_self(term_id_to_ref(node, glossary_docname))

        for node in paragraph.findall(definitions.DefRefNode):
            node["ref_source_doc"] = glossary_docname

        return paragraph, True


def select_definitions(
    storage: dict[str, list[GlossaryDefinition]],
    glossary_docname: str,
) -> list[GlossaryDefinition]:
    selected = []
    for term_id, defs in storage.items():
        preferred = select_preferred_definition(defs, glossary_docname)
        if preferred is not None:
            selected.append(preferred)
    return selected


def select_preferred_definition(defs, glossary_docname):
    non_glossary = [definition for definition in defs if definition.document != glossary_docname]
    pool = non_glossary or defs
    if not pool:
        return None
    return sorted(
        pool,
        key=lambda definition: (
            definition.document,
            definition.line or 0,
            definition.display_text,
        ),
    )[0]


def sort_definitions(definitions_list: Iterable[GlossaryDefinition]):
    return sorted(
        definitions_list,
        key=lambda definition: (
            title_sort_key(definition.display_text),
            definition.term_id,
        ),
    )


def title_sort_key(text):
    return [
        (int(chunk) if chunk.isdigit() else chunk.lower())
        for chunk in SPLIT_NUMBERS.split(text)
    ]


def collect_glossary_source_sections(document):
    sources = []
    for section in document.findall(nodes.section):
        if not isinstance(section.parent, nodes.section):
            continue

        try:
            section_id, _anchor = utils.section_id_and_anchor(section)
        except utils.NoSectionIdError:
            continue

        title_node = None
        for child in section.children:
            if isinstance(child, nodes.title):
                title_node = child
                break
        if title_node is None:
            continue

        title = title_node.astext()
        term_ids = tuple(
            node["def_id"]
            for node in section.findall(definitions.DefIdNode)
            if node["def_kind"] == TERM_KIND
        )
        sources.append(
            GlossarySectionSource(
                title=title,
                title_id=definitions.id_from_text(TERM_KIND, title),
                section_id=section_id,
                node=section,
                term_ids=term_ids,
            )
        )

    return sources


def index_glossary_sources(sources):
    by_term_id = {}
    by_title_id = {}
    for source in sources:
        for term_id in source.term_ids:
            by_term_id.setdefault(term_id, source)
        by_title_id.setdefault(source.title_id, source)
    return by_term_id, by_title_id


def sort_entries(entries: Iterable[GlossaryEntry]):
    return sorted(
        entries,
        key=lambda entry: (
            title_sort_key(entry.title),
            entry.term_id,
        ),
    )


def build_section_from_source(entry, glossary_docname, used_paragraph_ids, used_section_ids):
    source = entry.source_section
    if source is None:
        return None

    section_id = source.section_id
    if section_id in used_section_ids:
        section_id = stable_fls_id(
            "glossary-section:",
            entry.term_id,
            used_section_ids,
        )
    else:
        used_section_ids.add(section_id)

    section = nodes.section(ids=[section_id], names=[section_id])
    section += nodes.title("", entry.title)
    for child in source.node.children:
        if isinstance(child, nodes.title):
            continue
        section += child.deepcopy()

    replace_paragraph_ids(section, entry.term_id, used_paragraph_ids)
    for node in section.findall(definitions.DefRefNode):
        node["ref_source_doc"] = glossary_docname

    return section


def replace_paragraph_ids(section, term_id, used_paragraph_ids):
    index = 1
    for node in list(section.findall(definitions.DefIdNode)):
        if node["def_kind"] != PARAGRAPH_KIND:
            continue
        paragraph_id = stable_fls_id(
            "glossary:",
            f"{term_id}:{index}",
            used_paragraph_ids,
        )
        node.replace_self(definitions.DefIdNode(PARAGRAPH_KIND, paragraph_id))
        index += 1


def term_id_to_ref(node, docname):
    text = f"{node['def_text']} <{node['def_id']}>"
    return definitions.DefRefNode(TERM_KIND, docname, text)


def stable_fls_id(prefix, term_id, used_ids):
    counter = 1
    while True:
        suffix = "" if counter == 1 else f":{counter}"
        digest = hashlib.sha256(f"{prefix}{term_id}{suffix}".encode("utf-8")).digest()
        candidate = f"fls_{base62_encode(digest, ID_LENGTH)}"
        if candidate not in used_ids:
            used_ids.add(candidate)
            return candidate
        counter += 1


def base62_encode(data, length):
    value = int.from_bytes(data, "big")
    chars = []
    for _ in range(length):
        value, remainder = divmod(value, BASE62_BASE)
        chars.append(BASE62_ALPHABET[remainder])
    return "".join(chars)


def compute_signature(storage):
    items = []
    for term_id, defs in storage.items():
        for definition in defs:
            items.append(
                (
                    term_id,
                    definition.display_text,
                    definition.document,
                    definition.line or 0,
                )
            )

    items.sort()
    sha256 = hashlib.sha256()
    for item in items:
        sha256.update(repr(item).encode("utf-8"))
        sha256.update(b"\n")
    return sha256.hexdigest()


def apply_term_precedence(env):
    terms_storage = definitions.get_storage(env, definitions.terms)
    for term_id, defs in get_storage(env).items():
        preferred = select_preferred_definition(defs, "glossary")
        if preferred is None:
            continue

        if term_id in terms_storage:
            terms_storage[term_id].document = preferred.document
        else:
            terms_storage[term_id] = definitions.terms.Term(term_id, preferred.document)


def refresh_glossary_sections(env, document, glossary_docname):
    if not hasattr(env, "spec_sections"):
        return

    sections = []
    for section in document.findall(nodes.section):
        try:
            section_id, anchor = utils.section_id_and_anchor(section)
        except utils.NoSectionIdError:
            continue

        title_node = None
        for child in section.children:
            if isinstance(child, nodes.title):
                title_node = child
                break
        if title_node is None:
            continue

        sections.append(
            Section(
                id=section_id,
                title=title_node.astext(),
                anchor=anchor,
                document=glossary_docname,
            )
        )

    env.spec_sections = [
        section for section in env.spec_sections if section.document != glossary_docname
    ]
    env.spec_sections.extend(sections)


def refresh_glossary_paragraphs(env, document, glossary_docname):
    storage = definitions.get_storage(env, definitions.paragraphs)
    for paragraph_id, paragraph in list(storage.items()):
        if paragraph.document == glossary_docname:
            del storage[paragraph_id]

    counts = {}
    for node in document.findall(definitions.DefIdNode):
        if node["def_kind"] != PARAGRAPH_KIND:
            continue

        section_node = paragraphs.find_parent_of_type(node, nodes.section)
        if section_node is None:
            continue

        try:
            section_id, section_anchor = utils.section_id_and_anchor(section_node)
        except utils.NoSectionIdError:
            continue

        sequential = counts.get(section_id, 1)
        storage[node["def_id"]] = paragraphs.Paragraph(
            id=node["def_id"],
            document=glossary_docname,
            section_anchor=section_anchor,
            section_id=section_id,
            plaintext=paragraphs.plaintext_paragraph(node),
            sequential=sequential,
        )
        counts[section_id] = sequential + 1


def refresh_glossary_secnumbers(env, glossary_docname, sections):
    if glossary_docname not in env.toc_secnumbers:
        return

    secnumbers = env.toc_secnumbers[glossary_docname]
    prefix = None
    if "" in secnumbers and secnumbers[""]:
        prefix = secnumbers[""][0]
    if prefix is None:
        for secnum in secnumbers.values():
            if secnum:
                prefix = secnum[0]
                break
    if prefix is None:
        return

    new_secnumbers = {}
    if "" in secnumbers:
        new_secnumbers[""] = secnumbers[""]

    index = 1
    for section in sections:
        section_ids = section.get("ids", [])
        if not section_ids:
            continue
        anchor = "#" + section_ids[0]
        new_secnumbers[anchor] = (prefix, index)
        index += 1

    env.toc_secnumbers[glossary_docname] = new_secnumbers


def get_storage(env):
    key = "spec_glossary_terms"
    if not hasattr(env, key):
        setattr(env, key, {})
    return getattr(env, key)


def warn(message, location):
    logger = sphinx.util.logging.getLogger(__name__)
    logger.warning(message, location=location)


def setup(app):
    app.add_directive("spec-glossary", GlossaryDirective)
    app.add_node(GlossaryMarkerNode)
    app.add_env_collector(GlossaryCollector)
    app.add_post_transform(GlossaryTransform)

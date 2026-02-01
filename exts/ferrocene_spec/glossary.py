# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import textwrap
import string
from typing import Iterable, Optional
from urllib.parse import parse_qs, unquote, urlparse

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

GLOSSARY_DOCNAME = "glossary"
TERM_KIND = definitions.terms.NAME
SYNTAX_KIND = definitions.syntax.NAME
CODE_TERM_KIND = definitions.code_terms.NAME
PARAGRAPH_KIND = definitions.paragraphs.NAME

SPLIT_NUMBERS = re.compile(r"([0-9]+)")
GLOSSARY_ANCHOR = re.compile(r"^\.\. _fls_[A-Za-z0-9]+:\s*$")
GLOSSARY_TITLE = "Glossary"
GLOSSARY_STUB_ANCHOR = "fls_bc2qwbfibrcs"
GLOSSARY_GENERATED_COMMENT = (
    ".. This file is generated from chapter definitions. Do not edit."
)
ROLE_BY_KIND = {
    TERM_KIND: "t",
    SYNTAX_KIND: "s",
    CODE_TERM_KIND: "c",
    PARAGRAPH_KIND: "p",
}


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
        signature_changed = signature != previous
        if signature_changed:
            env.spec_glossary_signature = signature
            apply_term_precedence(env)

        override_changed = False
        force_glossary = False
        override = app.config.spec_glossary_source_override
        if override:
            override_signature = compute_override_signature(override)
            previous_override = getattr(env, "spec_glossary_override_signature", None)
            override_changed = override_signature != previous_override
            if override_changed:
                env.spec_glossary_override_signature = override_signature
            force_glossary = True

        if signature_changed or override_changed or force_glossary:
            if GLOSSARY_DOCNAME in env.found_docs:
                return [GLOSSARY_DOCNAME]
        return []


class GlossaryTransform(SphinxTransform):
    default_priority = 400

    def apply(self):
        for node in self.document.findall(GlossaryMarkerNode):
            self.replace_node(node)

    def replace_node(self, node):
        glossary_docname = node["docname"]
        definitions_storage = get_storage(self.env)
        selected = select_definitions(definitions_storage, glossary_docname)

        used_paragraph_ids = {
            item.id
            for item in definitions.get_storage(self.env, definitions.paragraphs).values()
        }
        used_section_ids = {
            section.id for section in getattr(self.env, "spec_sections", [])
        }

        sections = []
        for definition in sort_definitions(selected):
            paragraph, should_warn = self.build_paragraph(glossary_docname, definition)
            if paragraph is None:
                if should_warn:
                    warn(
                        f"missing glossary definition for '{definition.display_text}'",
                        node,
                    )
                continue

            paragraph_id = stable_fls_id(
                "glossary:",
                definition.term_id,
                used_paragraph_ids,
            )
            paragraph.insert(0, definitions.DefIdNode(PARAGRAPH_KIND, paragraph_id))

            section_id = stable_fls_id(
                "glossary-section:",
                definition.term_id,
                used_section_ids,
            )
            section = nodes.section(ids=[section_id], names=[section_id])
            section += nodes.title("", normalize_title_text(definition.display_text))
            section += paragraph
            sections.append(section)

        if not sections:
            if getattr(self.env, "spec_glossary_signature", None) is not None:
                warn("no glossary definitions found", node)
            write_generated_glossary(self.app, sections, self.document)
            node.parent.remove(node)
            return

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
        write_generated_glossary(self.app, sections, self.document)

    def build_paragraph(self, glossary_docname, definition):
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

        for node in list(paragraph.findall(definitions.DefIdNode)):
            if node["def_kind"] in (TERM_KIND, SYNTAX_KIND, CODE_TERM_KIND):
                node.replace_self(def_id_to_ref(node, glossary_docname))

        for node in paragraph.findall(definitions.DefRefNode):
            node["ref_source_doc"] = glossary_docname

        return paragraph, True


class GlossaryOverrideTransform(SphinxTransform):
    default_priority = 450

    def apply(self):
        docname = document_docname(self.env, self.document)
        if not docname:
            docname = getattr(self.env, "spec_glossary_override_docname", None)
        if docname != GLOSSARY_DOCNAME:
            return
        if not self.env.config.spec_glossary_source_override:
            return

        override_docname = getattr(self.env, "spec_glossary_override_docname", None)
        if override_docname and docname != override_docname:
            return

        targets = getattr(self.env, "spec_glossary_override_targets", {})
        if not targets:
            override_path = self.env.config.spec_glossary_source_override
            if override_path:
                try:
                    override_text = Path(override_path).read_text(encoding="utf-8")
                except OSError:
                    override_text = ""
                if override_text:
                    targets = parse_override_targets(override_text)
        if not targets:
            return

        updated_sections = []
        for section in self.document.findall(nodes.section):
            names = section.get("names", [])
            fls_name = None
            for name in names:
                if not name.startswith("fls_"):
                    continue
                if name == GLOSSARY_STUB_ANCHOR:
                    continue
                fls_name = name
                break
            if not fls_name:
                continue

            original_id = targets.get(fls_name, targets.get(fls_name.lower()))
            if not original_id:
                continue

            section["ids"] = [original_id]
            section["names"] = [original_id]
            updated_sections.append(section)

        if not updated_sections:
            return

        refresh_glossary_sections(self.env, self.document, GLOSSARY_DOCNAME)
        refresh_glossary_paragraphs(self.env, self.document, GLOSSARY_DOCNAME)
        refresh_glossary_secnumbers(self.env, GLOSSARY_DOCNAME, updated_sections)


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
    if not non_glossary:
        return None
    return sorted(
        non_glossary,
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


def def_id_to_ref(node, docname):
    kind = node["def_kind"]
    text = node["def_text"]
    if definitions.id_from_text(kind, text) != node["def_id"]:
        text = f"{text} <{node['def_id']}>"
    return definitions.DefRefNode(kind, docname, text)


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


def on_source_read(app, docname, source):
    if docname != GLOSSARY_DOCNAME:
        return
    override = app.config.spec_glossary_source_override
    if override:
        source_text = read_override_source(override, docname)
        source[0] = source_text
        record_override_targets(app.env, docname, source_text)
        return
    if stub_check_enabled(app.config.spec_glossary_stub_only_check):
        check_glossary_stub_only(source[0], docname)


def read_override_source(path, docname):
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        warn(
            f"failed to read glossary override source '{path}': {exc}",
            (docname, 1),
        )
        raise


def stub_check_enabled(value):
    if isinstance(value, str):
        return value.lower() not in {"0", "false", "no", "off"}
    return bool(value)


def check_glossary_stub_only(text, docname):
    allowed = {
        ".. default-domain:: spec",
        ".. informational-page::",
        ".. spec-glossary::",
        GLOSSARY_TITLE,
        "=" * len(GLOSSARY_TITLE),
    }
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped in allowed:
            continue
        if GLOSSARY_ANCHOR.match(stripped):
            continue
        if stripped.startswith("SPDX-") and line[: len(line) - len(line.lstrip())]:
            continue
        if line.lstrip().startswith(".. ") and "::" not in line:
            continue
        warn(
            "glossary stub contains unsupported content",
            (docname, lineno),
        )


def record_override_targets(env, docname, text):
    env.spec_glossary_override_targets = parse_override_targets(text)
    env.spec_glossary_override_docname = docname


def parse_override_targets(text):
    targets = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(".. _"):
            continue
        if not stripped.endswith(":"):
            continue
        target = stripped[len(".. _") : -1]
        if not target.startswith("fls_"):
            continue
        targets[target.lower()] = target
    return targets


def write_generated_glossary(app, sections, document):
    source_has_unicode = not document.astext().isascii()
    lines = glossary_header_lines()
    for section in sections:
        lines.extend(serialize_section(section))
    output = "\n".join(lines).rstrip() + "\n"
    if not source_has_unicode and not output.isascii():
        raise RuntimeError("generated glossary contains non-ASCII characters")

    build_dir = Path(app.outdir).parent
    generated_path = build_dir / "glossary.generated.rst"
    generated_path.write_text(output, encoding="utf-8")


def glossary_header_lines():
    return [
        ".. SPDX-License-Identifier: MIT OR Apache-2.0",
        "   SPDX-FileCopyrightText: The Ferrocene Developers",
        "   SPDX-FileCopyrightText: The Rust Project Contributors",
        "",
        ".. default-domain:: spec",
        "",
        ".. informational-page::",
        "",
        f".. _{GLOSSARY_STUB_ANCHOR}:",
        "",
        GLOSSARY_TITLE,
        "=" * len(GLOSSARY_TITLE),
        "",
        GLOSSARY_GENERATED_COMMENT,
        "",
    ]


def serialize_section(section):
    section_id = None
    if section.get("ids"):
        section_id = section["ids"][0]
    title_node = next(section.findall(nodes.title), None)
    title = title_node.astext() if title_node is not None else ""
    title = normalize_title_text(title)
    lines = []
    if section_id:
        lines.append(f".. _{section_id}:")
        lines.append("")
    lines.append(title)
    lines.append("^" * len(title))
    lines.append("")

    for child in section.children:
        if not isinstance(child, nodes.paragraph):
            continue
        paragraph_id = find_paragraph_id(child)
        if paragraph_id is None:
            continue
        extra_ids = [
            extra_id
            for extra_id in child.get("ids", [])
            if extra_id != paragraph_id
        ]
        for extra_id in extra_ids:
            lines.append(f".. _{extra_id}:")
            lines.append("")

        text = serialize_paragraph_text(child)
        if text.startswith(":\n"):
            lines.append(f":dp:`{paragraph_id}`:")
            lines.append(text[2:])
        else:
            lines.append(f":dp:`{paragraph_id}`")
            lines.append(text)
        lines.append("")
    return lines


def find_paragraph_id(paragraph):
    for node in paragraph.findall(definitions.DefIdNode):
        if node["def_kind"] == PARAGRAPH_KIND:
            return node["def_id"]
    return None


def serialize_paragraph_text(paragraph):
    raw = getattr(paragraph, "rawsource", "")
    if raw:
        text = strip_paragraph_id(raw)
        text = replace_definition_roles(text)
        text = textwrap.dedent(text)
        return text.strip("\n")

    parts = []
    for child in paragraph.children:
        if isinstance(child, definitions.DefIdNode) and child["def_kind"] == PARAGRAPH_KIND:
            continue
        parts.append(serialize_inline(child))
    return "".join(parts).replace("\n", " ").lstrip()


def serialize_inline(node):
    if isinstance(node, definitions.DefRefNode):
        return serialize_def_ref(node)
    if isinstance(node, definitions.DefIdNode):
        return serialize_def_id(node)
    if isinstance(node, nodes.emphasis):
        return f"*{serialize_children(node)}*"
    if isinstance(node, nodes.strong):
        return f"**{serialize_children(node)}**"
    if isinstance(node, nodes.literal):
        return f"``{serialize_children(node)}``"
    if isinstance(node, nodes.reference):
        refuri = node.get("refuri")
        if refuri:
            literal_text = find_literal_text(node)
            if literal_text:
                std_target = std_target_from_refuri(refuri)
                if std_target:
                    if std_target != literal_text:
                        literal_text = f"{literal_text} <{std_target}>"
                    return f":std:`{literal_text}`"
            text = serialize_children(node)
            return f"`{text} <{refuri}>`__"
        return serialize_children(node)
    if isinstance(node, nodes.inline):
        return serialize_children(node)
    return node.astext()


def serialize_children(node):
    if not node.children:
        return node.astext()
    return "".join(serialize_inline(child) for child in node.children)


def strip_paragraph_id(text):
    return re.sub(r"^\s*:dp:`[^`]+`\s*", "", text, count=1)


def replace_definition_roles(text):
    text = text.replace(":dt:`", ":t:`")
    text = text.replace(":ds:`", ":s:`")
    text = text.replace(":dc:`", ":c:`")
    return text


def normalize_title_text(text):
    return " ".join(text.split())


def find_literal_text(node):
    for child in node.children:
        if isinstance(child, nodes.literal):
            return child.astext()
    return None


def std_target_from_refuri(refuri):
    parsed = urlparse(refuri)
    query = parse_qs(parsed.query)
    search = query.get("search", [])
    if not search:
        return None
    return unquote(search[0])


def next_section_sibling(target):
    parent = target.parent
    if parent is None:
        return None
    try:
        index = parent.children.index(target)
    except ValueError:
        return None
    for sibling in parent.children[index + 1 :]:
        if isinstance(sibling, nodes.section):
            return sibling
    return None


def document_docname(env, document):
    docname = getattr(env, "docname", None)
    if docname:
        return docname
    source = document.get("source")
    if not source:
        return None
    return Path(source).stem


def serialize_def_ref(node):
    role = kind_to_role(node["ref_kind"])
    if role is None:
        return node.astext()
    text = node["ref_text"]
    target = node["ref_target"]
    if text != target:
        text = f"{text} <{target}>"
    return f":{role}:`{text}`"


def serialize_def_id(node):
    role = kind_to_role(node["def_kind"])
    if role is None:
        return node.astext()
    text = node["def_text"]
    target = node["def_id"]
    if definitions.id_from_text(node["def_kind"], text) != target:
        text = f"{text} <{target}>"
    return f":d{role}:`{text}`"


def kind_to_role(kind):
    return ROLE_BY_KIND.get(kind)


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


def compute_override_signature(path):
    sha256 = hashlib.sha256()
    try:
        content = Path(path).read_text(encoding="utf-8")
    except OSError:
        content = ""
    sha256.update(content.encode("utf-8"))
    return sha256.hexdigest()


def apply_term_precedence(env):
    terms_storage = definitions.get_storage(env, definitions.terms)
    for term_id, defs in get_storage(env).items():
        preferred = select_preferred_definition(defs, GLOSSARY_DOCNAME)
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
    app.add_post_transform(GlossaryOverrideTransform)
    app.add_config_value(
        "spec_glossary_source_override",
        None,
        "env",
        types=[str, type(None)],
    )
    app.add_config_value(
        "spec_glossary_stub_only_check",
        True,
        "env",
        types=[bool],
    )
    app.connect("source-read", on_source_read)

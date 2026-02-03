# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

from dataclasses import dataclass
from pathlib import Path
from docutils import nodes
from docutils.parsers.rst import directives
from docutils.statemachine import StringList
from sphinx.util.docutils import SphinxDirective
from sphinx.environment.collectors import EnvironmentCollector
from sphinx.util import logging

VALID_KINDS = ("term", "code", "syntax")


class GlossaryEntryNode(nodes.Element):
    __slots__ = ("glossary_lines", "chapter_lines")
    glossary_lines: list[str] | None
    chapter_lines: list[str] | None


def _parse_bool_option(argument):
    if argument is None:
        raise ValueError("propagate requires true or false")
    value = argument.strip().lower()
    if value not in ("true", "false"):
        raise ValueError("propagate requires true or false")
    return value == "true"


@dataclass
class GlossaryEntryData:
    term: str
    kind: str
    propagate: bool
    glossary_lines: list[str] | None
    chapter_lines: list[str] | None
    document: str
    source: str | None
    line: int | None


class GlossaryEntryDirective(SphinxDirective):
    required_arguments = 1
    has_content = True
    final_argument_whitespace = True
    option_spec = {
        "kind": lambda argument: directives.choice(argument, VALID_KINDS),
        "propagate": _parse_bool_option,
    }

    def run(self):
        term = self.arguments[0].strip()
        if not term:
            warn("glossary-entry requires a term argument", self.get_location())
            return []

        glossary_lines, chapter_lines = parse_section_blocks(
            list(self.content), self.get_location()
        )

        if glossary_lines is None and chapter_lines is None:
            warn("glossary-entry requires :glossary: or :chapter:", self.get_location())
            return []

        propagate = self.options.get("propagate", False)
        kind = self.options.get("kind", "term")

        node = GlossaryEntryNode()
        source, line = self.get_source_info()
        node["term"] = term
        node["kind"] = kind
        node["propagate"] = propagate
        node.glossary_lines = glossary_lines
        node.chapter_lines = chapter_lines
        node["source"] = source
        node["line"] = line
        node.source = source
        node.line = line

        result: list[nodes.Node] = [node]
        if chapter_lines is not None:
            result.extend(parse_chapter_lines(self, chapter_lines, source, line))
        return result


class GlossaryIncludeDirective(SphinxDirective):
    required_arguments = 1
    has_content = False
    option_spec = {
        "start-after": directives.unchanged_required,
        "tag": directives.unchanged_required,
    }

    def run(self):
        logger = logging.getLogger(__name__)
        tag_expr = self.options.get("tag")
        include_path = directives.path(self.arguments[0])
        if tag_expr and not self.env.app.tags.eval_condition(tag_expr):
            logger.info(
                "glossary-include: skipped tag=%r include=%s",
                tag_expr,
                include_path,
            )
            return []

        source = self.get_source_info()[0]
        if source:
            source_dir = Path(source).parent
        else:
            source_dir = Path(self.env.srcdir)
        resolved = (source_dir / include_path).resolve()
        if not resolved.is_file():
            warn(f"missing include file: {resolved}", self.get_location())
            return []

        logger.info(
            "glossary-include: using tag=%r include=%s",
            tag_expr,
            resolved,
        )

        text = resolved.read_text(encoding="utf-8")
        lines = text.splitlines()
        start_after = self.options.get("start-after")
        if start_after:
            lines = lines_after_marker(lines, start_after, resolved, self.get_location())

        viewlist = StringList()
        for offset, content in enumerate(lines):
            viewlist.append(content, str(resolved), offset + 1)

        container = nodes.container()
        self.state.nested_parse(viewlist, self.content_offset, container, match_titles=True)
        return list(container.children)


def parse_section_blocks(
    content_lines: list[str], location
) -> tuple[list[str] | None, list[str] | None]:
    sections: dict[str, list[str] | None] = {"glossary": None, "chapter": None}
    current: str | None = None
    buffer: list[str] = []

    for line in content_lines:
        stripped = line.strip()
        if stripped in (":glossary:", ":chapter:") and line.startswith(":"):
            if current is not None:
                sections[current] = dedent_block(buffer)
            current = stripped.strip(":")
            if sections[current] is not None:
                warn(f"duplicate :{current}: block", location)
            buffer = []
            continue

        if current is None:
            if stripped:
                warn(
                    "glossary-entry content must be inside :glossary: or :chapter:",
                    location,
                )
            continue

        buffer.append(line)

    if current is not None:
        sections[current] = dedent_block(buffer)

    sections["glossary"] = normalize_block(sections["glossary"], location, "glossary")
    sections["chapter"] = normalize_block(sections["chapter"], location, "chapter")

    return sections["glossary"], sections["chapter"]


def normalize_block(
    block_lines: list[str] | None, location, name: str
) -> list[str] | None:
    if block_lines is None:
        return None
    if not any(line.strip() for line in block_lines):
        warn(f":{name}: block is empty", location)
        return None
    return block_lines


def dedent_block(lines: list[str]) -> list[str]:
    indents = [len(line) - len(line.lstrip(" ")) for line in lines if line.strip()]
    indent = min(indents) if indents else 0
    return [line[indent:] if len(line) >= indent else "" for line in lines]


def parse_chapter_lines(directive, lines, source, line):
    viewlist = StringList()
    if line is None:
        line = 0
    for offset, content in enumerate(lines):
        viewlist.append(content, source, line + offset)

    container = nodes.container()
    directive.state.nested_parse(viewlist, directive.content_offset, container)
    return list(container.children)


def lines_after_marker(lines, marker, path, location):
    for index, line in enumerate(lines):
        if marker in line:
            return lines[index + 1 :]
    warn(f"start-after marker not found in {path}", location)
    return lines


class GlossaryEntryCollector(EnvironmentCollector):
    def clear_doc(self, app, env, docname):
        storage = get_storage(env)
        for term, entry in list(storage.items()):
            if entry.document == docname:
                del storage[term]

    def merge_other(self, app, env, docnames, other):
        current = get_storage(env)
        other_storage = get_storage(other)
        for entry in other_storage.values():
            if entry.document in docnames:
                current[entry.term] = entry

    def process_doc(self, app, doctree):
        storage = get_storage(app.env)
        for node in doctree.findall(GlossaryEntryNode):
            term = node["term"]
            if term in storage:
                warn(
                    f"duplicate glossary-entry for {term}",
                    (node.get("source"), node.get("line")),
                )
                continue

            storage[term] = GlossaryEntryData(
                term=term,
                kind=node["kind"],
                propagate=node["propagate"],
                glossary_lines=node.glossary_lines,
                chapter_lines=node.chapter_lines,
                document=app.env.docname,
                source=node.get("source"),
                line=node.get("line"),
            )


def get_storage(env):
    key = "spec_glossary_entries"
    if not hasattr(env, key):
        setattr(env, key, {})
    return getattr(env, key)


def visit_glossary_entry_node(self, node):
    raise nodes.SkipNode


def depart_glossary_entry_node(self, node):
    pass


def warn(message, location):
    logger = logging.getLogger(__name__)
    logger.warning(message, location=location)


def setup(app):
    app.add_node(
        GlossaryEntryNode,
        html=(visit_glossary_entry_node, depart_glossary_entry_node),
        latex=(visit_glossary_entry_node, depart_glossary_entry_node),
        text=(visit_glossary_entry_node, depart_glossary_entry_node),
        man=(visit_glossary_entry_node, depart_glossary_entry_node),
        texinfo=(visit_glossary_entry_node, depart_glossary_entry_node),
        xml=(visit_glossary_entry_node, depart_glossary_entry_node),
    )
    app.add_env_collector(GlossaryEntryCollector)

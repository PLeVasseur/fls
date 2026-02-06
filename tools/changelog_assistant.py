#!/usr/bin/env -S uv run
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


NORMATIVE_KEYWORDS = ("shall", "must", "may", "only", "unless", "except", "not", "any", "all", "none")


CHANGE_TAG_ORDER = [
    "paragraph-added",
    "paragraph-removed",
    "paragraph-changed",
    "role-change",
    "term-def-added",
    "term-def-removed",
    "term-ref-added",
    "term-ref-removed",
    "syntax-def-added",
    "syntax-def-removed",
    "syntax-ref-added",
    "syntax-ref-removed",
    "literal-change",
    "list-structure-change",
    "section-added",
    "section-removed",
    "definition-relocated",
    "normative-shift",
]


def run_git(root, args, check=True, strip=True):
    process = subprocess.run(
        ["git", *args],
        cwd=root,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return process.stdout.strip() if strip else process.stdout


def file_lines(output):
    return [line.strip() for line in output.splitlines() if line.strip()]


def default_base_ref(root):
    for candidate in ("origin/main", "main", "HEAD~1"):
        try:
            run_git(root, ["rev-parse", "--verify", candidate])
            return candidate
        except subprocess.CalledProcessError:
            continue
    raise RuntimeError("unable to determine a base ref")


def discover_changed_src_files(root, base_ref):
    committed = set(
        file_lines(run_git(root, ["diff", "--name-only", f"{base_ref}...HEAD", "--", "src"]))
    )
    staged = set(file_lines(run_git(root, ["diff", "--name-only", "--cached", "--", "src"])))
    unstaged = set(file_lines(run_git(root, ["diff", "--name-only", "--", "src"])))
    untracked = set(
        file_lines(run_git(root, ["ls-files", "--others", "--exclude-standard", "--", "src"]))
    )

    all_paths = committed | staged | unstaged | untracked
    return sorted(
        path for path in all_paths if path.startswith("src/") and path != "src/changelog.rst"
    )


def clean_build_directory(path):
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def build_head(root, out_root):
    doctrees = out_root / "doctrees"
    output = out_root / "out"
    doctrees.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "sphinx-build",
            "-b",
            "dummy",
            "-E",
            "-a",
            "-d",
            str(doctrees),
            str(root / "src"),
            str(output),
        ],
        cwd=root,
        check=True,
    )
    return output / "paragraph-ids-rich.json"


def materialize_base_snapshot(root, base_ref, snapshot_root):
    snapshot_root.mkdir(parents=True, exist_ok=True)
    (snapshot_root / "src").mkdir(parents=True, exist_ok=True)

    for link_name in ("exts", "themes"):
        target = root / link_name
        link = snapshot_root / link_name
        link.symlink_to(target, target_is_directory=True)

    paths = file_lines(run_git(root, ["ls-tree", "-r", "--name-only", base_ref, "--", "src", "version.rst"]))
    for relative in paths:
        destination = snapshot_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = run_git(root, ["show", f"{base_ref}:{relative}"], strip=False)
        destination.write_text(content, encoding="utf-8")


def build_base(root, base_ref, out_root):
    snapshot = out_root / "snapshot"
    materialize_base_snapshot(root, base_ref, snapshot)

    doctrees = out_root / "doctrees"
    output = out_root / "out"
    doctrees.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "sphinx-build",
            "-b",
            "dummy",
            "-E",
            "-a",
            "-d",
            str(doctrees),
            str(snapshot / "src"),
            str(output),
        ],
        cwd=snapshot,
        check=True,
    )
    return output / "paragraph-ids-rich.json"


def flatten_paragraphs(payload):
    paragraphs = {}
    for document in payload["documents"]:
        for section in document["sections"]:
            for paragraph in section["paragraphs"]:
                paragraphs[paragraph["id"]] = paragraph
    return paragraphs


def map_definitions(definition_items):
    return {item["id"]: item for item in definition_items}


def section_map(payload):
    return {item["id"]: item for item in payload["sections"]}


def sorted_tags(tags):
    seen = set(tags)
    return [tag for tag in CHANGE_TAG_ORDER if tag in seen]


def keyword_counts(text):
    lowered = text.lower()
    return {keyword: len(re.findall(rf"\b{re.escape(keyword)}\b", lowered)) for keyword in NORMATIVE_KEYWORDS}


def compare_definitions(base_defs, head_defs, added_tag, removed_tag, changes):
    base_map = map_definitions(base_defs)
    head_map = map_definitions(head_defs)

    for added in sorted(set(head_map) - set(base_map)):
        changes.append({"type": added_tag.replace("-", "_"), "id": added, "tag": added_tag})

    for removed in sorted(set(base_map) - set(head_map)):
        changes.append({"type": removed_tag.replace("-", "_"), "id": removed, "tag": removed_tag})

    for common in sorted(set(base_map) & set(head_map)):
        if base_map[common]["document"] != head_map[common]["document"]:
            changes.append(
                {
                    "type": "definition_relocated",
                    "id": common,
                    "tag": "definition-relocated",
                    "from": base_map[common]["document"],
                    "to": head_map[common]["document"],
                }
            )


def compare_payloads(base_payload, head_payload):
    changes = []
    tags = set()

    base_paragraphs = flatten_paragraphs(base_payload)
    head_paragraphs = flatten_paragraphs(head_payload)

    base_ids = set(base_paragraphs)
    head_ids = set(head_paragraphs)

    for paragraph_id in sorted(head_ids - base_ids):
        changes.append({"type": "paragraph_added", "paragraph_id": paragraph_id, "tag": "paragraph-added"})
        tags.add("paragraph-added")

    for paragraph_id in sorted(base_ids - head_ids):
        changes.append({"type": "paragraph_removed", "paragraph_id": paragraph_id, "tag": "paragraph-removed"})
        tags.add("paragraph-removed")

    for paragraph_id in sorted(base_ids & head_ids):
        base_para = base_paragraphs[paragraph_id]
        head_para = head_paragraphs[paragraph_id]

        if base_para.get("markup_checksum") != head_para.get("markup_checksum"):
            changes.append(
                {
                    "type": "paragraph_changed",
                    "paragraph_id": paragraph_id,
                    "tag": "paragraph-changed",
                    "base_checksum": base_para.get("checksum"),
                    "head_checksum": head_para.get("checksum"),
                }
            )
            tags.add("paragraph-changed")

        if base_para.get("role_inventory") != head_para.get("role_inventory"):
            changes.append(
                {
                    "type": "role_change",
                    "paragraph_id": paragraph_id,
                    "tag": "role-change",
                    "base_roles": base_para.get("role_inventory", {}),
                    "head_roles": head_para.get("role_inventory", {}),
                }
            )
            tags.add("role-change")

        base_roles = base_para.get("role_inventory", {})
        head_roles = head_para.get("role_inventory", {})
        for key, add_tag, remove_tag in (
            ("t", "term-ref-added", "term-ref-removed"),
            ("s", "syntax-ref-added", "syntax-ref-removed"),
        ):
            delta = head_roles.get(key, 0) - base_roles.get(key, 0)
            if delta > 0:
                changes.append(
                    {
                        "type": add_tag.replace("-", "_"),
                        "paragraph_id": paragraph_id,
                        "count": delta,
                        "tag": add_tag,
                    }
                )
                tags.add(add_tag)
            elif delta < 0:
                changes.append(
                    {
                        "type": remove_tag.replace("-", "_"),
                        "paragraph_id": paragraph_id,
                        "count": abs(delta),
                        "tag": remove_tag,
                    }
                )
                tags.add(remove_tag)

        if base_para.get("literal_inventory") != head_para.get("literal_inventory"):
            changes.append({"type": "literal_change", "paragraph_id": paragraph_id, "tag": "literal-change"})
            tags.add("literal-change")

        if base_para.get("list_structure") != head_para.get("list_structure"):
            changes.append(
                {
                    "type": "list_structure_change",
                    "paragraph_id": paragraph_id,
                    "tag": "list-structure-change",
                }
            )
            tags.add("list-structure-change")

        if keyword_counts(base_para.get("plaintext", "")) != keyword_counts(head_para.get("plaintext", "")):
            changes.append(
                {
                    "type": "normative_shift",
                    "paragraph_id": paragraph_id,
                    "tag": "normative-shift",
                }
            )
            tags.add("normative-shift")

    compare_definitions(
        base_payload["definitions"]["term"],
        head_payload["definitions"]["term"],
        "term-def-added",
        "term-def-removed",
        changes,
    )
    compare_definitions(
        base_payload["definitions"]["syntax"],
        head_payload["definitions"]["syntax"],
        "syntax-def-added",
        "syntax-def-removed",
        changes,
    )

    base_sections = section_map(base_payload)
    head_sections = section_map(head_payload)

    for section_id in sorted(set(head_sections) - set(base_sections)):
        changes.append({"type": "section_added", "section_id": section_id, "tag": "section-added"})
        tags.add("section-added")

    for section_id in sorted(set(base_sections) - set(head_sections)):
        changes.append({"type": "section_removed", "section_id": section_id, "tag": "section-removed"})
        tags.add("section-removed")

    for change in changes:
        tag = change.get("tag")
        if tag:
            tags.add(tag)

    return {"changes": changes, "tags": sorted_tags(tags)}


def read_release_from_version(version_path):
    content = version_path.read_text(encoding="utf-8")
    match = re.search(r"\|spec_version\|\s+replace::\s+([0-9]+\.[0-9]+\.[0-9]+)", content)
    if not match:
        raise RuntimeError("unable to parse version.rst")
    return match.group(1)


def infer_pr_and_title(root):
    subject = run_git(root, ["log", "-1", "--format=%s"])
    pr_url = None
    title = subject

    pull_match = re.search(r"https://github.com/rust-lang/rust/pull/(\d+)", subject)
    shorthand = re.search(r"rust-lang/rust#(\d+)", subject)
    if pull_match:
        pr_url = pull_match.group(0)
    elif shorthand:
        pr_url = f"https://github.com/rust-lang/rust/pull/{shorthand.group(1)}"

    return pr_url, title


def heading_for_release(release):
    return f"Language changes in Rust {release}"


def extract_release_section(lines, release):
    title = heading_for_release(release)
    start = None
    for index, line in enumerate(lines):
        if line.strip() == title:
            start = index
            break
    if start is None:
        return None, None, None

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("Language changes in Rust "):
            end = index
            break
    return start, start + 2, end


def ensure_release_section(changelog_path, release):
    lines = changelog_path.read_text(encoding="utf-8").splitlines()
    start, _, _ = extract_release_section(lines, release)
    if start is not None:
        return lines

    insert_at = None
    for index, line in enumerate(lines):
        if line.startswith("Language changes in Rust "):
            insert_at = index
            break
    if insert_at is None:
        insert_at = len(lines)

    heading = heading_for_release(release)
    new_section = [heading, "-" * len(heading), "", ""]
    lines = lines[:insert_at] + new_section + lines[insert_at:]
    return lines


def paragraph_ids_requiring_coverage(changes):
    ids = set()
    for change in changes:
        paragraph_id = change.get("paragraph_id")
        if paragraph_id:
            ids.add(paragraph_id)
    return ids


def release_section_text(lines, release):
    start, body_start, end = extract_release_section(lines, release)
    if start is None:
        return ""
    return "\n".join(lines[body_start:end])


def changelog_coverage_failures(lines, release, changes, require_tags):
    failures = []
    body = release_section_text(lines, release)
    if not body:
        failures.append(f"missing release section: {heading_for_release(release)}")
        return failures

    existing_ids = set(re.findall(r":p:`([^`]+)`", body))
    required_ids = paragraph_ids_requiring_coverage(changes)
    missing = sorted(required_ids - existing_ids)
    if missing:
        failures.append("missing paragraph ids in changelog section: " + ", ".join(missing))

    if require_tags:
        bullet_blocks = re.findall(r"(?m)^- .*(?:\n(?:\n|  .*)*)", body)
        for block in bullet_blocks:
            if "Change tags:" not in block:
                first_line = block.splitlines()[0]
                failures.append(f"entry missing Change tags: {first_line}")

    return failures


def entry_lines(title, pr_url, tags, changes):
    if title and pr_url:
        first = f"- `{title} <{pr_url}>`_"
    else:
        first = "- TODO: fill release item title and upstream PR URL"

    grouped = defaultdict(list)
    for change in changes:
        grouped[change["type"]].append(change)

    lines = [first, "", f"  - Change tags: {', '.join(tags)}"]

    for label, change_type in (
        ("Added paragraphs", "paragraph_added"),
        ("Removed paragraphs", "paragraph_removed"),
        ("Changed paragraphs", "paragraph_changed"),
        ("Role changes", "role_change"),
        ("Term definitions added", "term_def_added"),
        ("Term definitions removed", "term_def_removed"),
        ("Term references added", "term_ref_added"),
        ("Term references removed", "term_ref_removed"),
        ("Syntax definitions added", "syntax_def_added"),
        ("Syntax definitions removed", "syntax_def_removed"),
        ("Syntax references added", "syntax_ref_added"),
        ("Syntax references removed", "syntax_ref_removed"),
        ("Literal changes", "literal_change"),
        ("List structure changes", "list_structure_change"),
        ("Sections added", "section_added"),
        ("Sections removed", "section_removed"),
        ("Definitions relocated", "definition_relocated"),
        ("Normative shifts", "normative_shift"),
    ):
        records = grouped.get(change_type)
        if not records:
            continue
        lines.append(f"  - {label}:")
        for record in records:
            if "paragraph_id" in record:
                lines.append(f"    - :p:`{record['paragraph_id']}`")
            elif "section_id" in record:
                lines.append(f"    - :ref:`{record['section_id']}`")
            else:
                lines.append(f"    - {record.get('id', '<unknown>')}")

    lines.append("")
    return lines


def update_changelog(changelog_path, release, title, pr_url, tags, changes):
    lines = ensure_release_section(changelog_path, release)
    _, body_start, body_end = extract_release_section(lines, release)
    if body_start is None or body_end is None:
        raise RuntimeError("unable to place release section")

    lines = lines[:body_end] + entry_lines(title, pr_url, tags, changes) + lines[body_end:]
    changelog_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def write_reports(json_path, markdown_path, release, base_ref, changed_files, diff_result):
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "release": release,
        "base": base_ref,
        "changed_src_files": changed_files,
        "tags": diff_result["tags"],
        "changes": diff_result["changes"],
    }
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    lines = [
        f"# Changelog Diff Report ({release})",
        "",
        f"Base ref: `{base_ref}`",
        "",
        "## Changed files",
    ]
    if changed_files:
        lines.extend([f"- `{path}`" for path in changed_files])
    else:
        lines.append("- none")

    lines.extend(["", "## Tags", ""])
    if diff_result["tags"]:
        lines.extend([f"- `{tag}`" for tag in diff_result["tags"]])
    else:
        lines.append("- none")

    lines.extend(["", "## Changes", ""])
    if diff_result["changes"]:
        for change in diff_result["changes"]:
            target = change.get("paragraph_id") or change.get("section_id") or change.get("id", "")
            lines.append(f"- `{change['type']}` {target}")
    else:
        lines.append("- none")

    markdown_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def parse_report_paths(root, emit_report):
    if emit_report:
        report_base = Path(emit_report)
        if not report_base.is_absolute():
            report_base = root / report_base
    else:
        report_base = root / "build" / "changelog-diff"

    if report_base.suffix:
        json_path = report_base
        markdown_path = report_base.with_suffix(".md")
    else:
        json_path = report_base.with_suffix(".json")
        markdown_path = report_base.with_suffix(".md")
    return json_path, markdown_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify changelog coverage")
    parser.add_argument("--update", action="store_true", help="update src/changelog.rst")
    parser.add_argument("--release", help="release version, defaults to version.rst")
    parser.add_argument("--base", help="git base ref")
    parser.add_argument("--upstream-pr", help="upstream rust-lang/rust PR URL")
    parser.add_argument("--title", help="release item title")
    parser.add_argument("--emit-report", help="base path for report files")
    parser.add_argument("--require-tags", action="store_true", help="require Change tags lines")
    args = parser.parse_args()

    if not args.check and not args.update:
        args.check = True

    root = Path(__file__).resolve().parents[1]
    release = args.release or read_release_from_version(root / "version.rst")
    base_ref = args.base or default_base_ref(root)
    changed_files = discover_changed_src_files(root, base_ref)

    json_path, markdown_path = parse_report_paths(root, args.emit_report)

    if not changed_files:
        diff_result = {"changes": [], "tags": []}
        write_reports(json_path, markdown_path, release, base_ref, changed_files, diff_result)
        print("no src changes detected")
        return 0

    build_root = root / "build"
    base_root = build_root / "changelog-base"
    head_root = build_root / "changelog-head"
    clean_build_directory(base_root)
    clean_build_directory(head_root)

    base_artifact = build_base(root, base_ref, base_root)
    head_artifact = build_head(root, head_root)

    base_payload = json.loads(base_artifact.read_text(encoding="utf-8"))
    head_payload = json.loads(head_artifact.read_text(encoding="utf-8"))

    diff_result = compare_payloads(base_payload, head_payload)
    write_reports(json_path, markdown_path, release, base_ref, changed_files, diff_result)

    inferred_pr, inferred_title = infer_pr_and_title(root)
    pr_url = args.upstream_pr or inferred_pr
    title = args.title or inferred_title

    changelog_path = root / "src" / "changelog.rst"

    if args.update:
        update_changelog(
            changelog_path,
            release,
            title if pr_url and title else None,
            pr_url if pr_url else None,
            diff_result["tags"],
            diff_result["changes"],
        )
        if not pr_url or not title:
            print("warning: inserted TODO changelog entry because metadata is incomplete")

    if args.check:
        lines = changelog_path.read_text(encoding="utf-8").splitlines()
        failures = changelog_coverage_failures(
            lines,
            release,
            diff_result["changes"],
            require_tags=args.require_tags,
        )
        if failures:
            for failure in failures:
                print(f"error: {failure}")
            print(f"report: {json_path}")
            return 1

    print(f"report: {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

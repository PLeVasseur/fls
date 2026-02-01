#!/usr/bin/env -S uv run
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers
# SPDX-FileCopyrightText: The Rust Project Contributors

import difflib
import os
from pathlib import Path
import argparse
import platform
import subprocess
import shutil

# Automatically watch the following extra directories when --serve is used.
EXTRA_WATCH_DIRS = ["exts", "themes"]
DELTA_VERSION = "0.18.2"
DEFAULT_DELTA_CONFIG = """[delta]
    syntax-theme = none
    line-numbers = false
    side-by-side = false
    navigate = false
"""


def build_docs(
    root,
    builder,
    clear,
    serve,
    debug,
    output_dir_name=None,
    doctree_dir_name=None,
    extra_defines=None,
):
    dest = root / "build"
    output_dir = dest / (output_dir_name or builder)
    doctree_dir = dest / (doctree_dir_name or "doctrees")

    args = ["-b", builder, "-d", doctree_dir]
    if debug:
        # Disable parallel builds and show exceptions in debug mode.
        #
        # We can't show exceptions in parallel mode because in parallel mode
        # all exceptions will be swallowed up by Python's multiprocessing.
        # That's also why we don't show exceptions outside of debug mode.
        args += ["-j", "1", "-T"]
    else:
        # Enable parallel builds:
        args += ["-j", "auto"]
    if clear:
        if output_dir.exists():
            shutil.rmtree(output_dir)
        if doctree_dir.exists():
            shutil.rmtree(doctree_dir)
        # Using a fresh environment
        args.append("-E")
    if serve:
        for extra_watch_dir in EXTRA_WATCH_DIRS:
            extra_watch_dir = root / extra_watch_dir
            if extra_watch_dir.exists():
                args += ["--watch", extra_watch_dir]
    else:
        # Error out at the *end* of the build if there are warnings:
        args += ["-W", "--keep-going"]

    commit = current_git_commit(root)
    if commit is not None:
        args += ["-D", f"html_theme_options.commit={commit}"]

    if extra_defines:
        for key, value in extra_defines.items():
            if value is None:
                continue
            args += ["-D", f"{key}={value}"]

    try:
        subprocess.run(
            [
                "sphinx-autobuild" if serve else "sphinx-build",
                *args,
                root / "src",
                output_dir,
            ],
            check=True,
        )
    except KeyboardInterrupt:
        exit(1)
    except subprocess.CalledProcessError:
        print("\nhint: if you see an exception, pass --debug to see the full traceback")
        exit(1)

    return dest / builder


def build_linkchecker(root):
    repo = root / ".linkchecker"
    src = repo / "src" / "tools" / "linkchecker"
    bin = src / "target" / "release" / "linkchecker"

    if not src.is_dir():
        subprocess.run(["git", "init", repo], check=True)

        def git(args):
            subprocess.run(["git", *args], cwd=repo, check=True)

        # Avoid fetching blobs unless needed by the sparse checkout
        git(["remote", "add", "origin", "https://github.com/rust-lang/rust"])
        git(["config", "remote.origin.promisor", "true"])
        git(["config", "remote.origin.partialCloneFilter", "blob:none"])

        # Checkout only the linkchecker tool rather than the whole repo
        git(["config", "core.sparsecheckout", "true"])
        with open(repo / ".git" / "info" / "sparse-checkout", "w") as f:
            f.write("/src/tools/linkchecker/")

        # Avoid fetching the whole history
        git(["fetch", "--depth=1", "origin", "main"])
        git(["checkout", "main"])

    if not bin.is_file():
        subprocess.run(["cargo", "build", "--release"], cwd=src, check=True)

    return bin


def check_generated_glossary(root, debug, clear):
    build_docs(root, "html", clear=clear, serve=False, debug=debug)

    generated_source = root / "build" / "glossary.generated.rst"
    if not generated_source.is_file():
        print("error: build/glossary.generated.rst was not produced")
        exit(1)

    build_docs(
        root,
        "html",
        clear=clear,
        serve=False,
        debug=debug,
        output_dir_name="html-generated",
        doctree_dir_name="doctrees-generated",
        extra_defines={
            "spec_glossary_source_override": generated_source,
            "spec_glossary_stub_only_check": False,
        },
    )

    base_html = root / "build" / "html" / "glossary.html"
    generated_html = root / "build" / "html-generated" / "glossary.html"
    base_paragraphs = root / "build" / "html" / "paragraph-ids.json"
    generated_paragraphs = root / "build" / "html-generated" / "paragraph-ids.json"

    comparisons = [
        (
            base_html,
            generated_html,
            root / "build" / "glossary-compare" / "glossary.html.diff",
        ),
        (
            base_paragraphs,
            generated_paragraphs,
            root
            / "build"
            / "glossary-compare"
            / "paragraph-ids.json.diff",
        ),
    ]

    diffs = []
    for left, right, output_path in comparisons:
        matches, diff_text = compare_files(left, right)
        if not matches:
            diffs.append((diff_text, output_path))

    if not diffs:
        return

    delta_path = delta_binary_path(root)
    if not delta_path.is_file():
        print("error: delta is required; run tools/install-delta.py")
        exit(1)

    config_path = ensure_delta_config(root)
    for diff_text, output_path in diffs:
        write_delta_diff(delta_path, config_path, diff_text, output_path)

    print("error: generated glossary output differs; see build/glossary-compare")
    exit(1)


def compare_files(left, right):
    if left.read_bytes() == right.read_bytes():
        return True, ""
    left_text = left.read_text(encoding="utf-8", errors="replace").splitlines()
    right_text = right.read_text(encoding="utf-8", errors="replace").splitlines()
    diff = difflib.unified_diff(
        left_text,
        right_text,
        fromfile=str(left),
        tofile=str(right),
        lineterm="",
    )
    return False, "\n".join(diff) + "\n"


def write_delta_diff(delta_path, config_path, diff_text, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            str(delta_path),
            "--config",
            str(config_path),
            "--color-only",
        ],
        input=diff_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    output = result.stdout or diff_text
    output_path.write_text(output, encoding="utf-8")


def delta_binary_path(root):
    system = platform.system().lower()
    exe = "delta.exe" if system.startswith("win") else "delta"
    return root / ".cache" / "delta" / DELTA_VERSION / delta_target() / exe


def delta_target():
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        if machine in ("x86_64", "amd64"):
            return "x86_64-unknown-linux-gnu"
        if machine in ("aarch64", "arm64"):
            return "aarch64-unknown-linux-gnu"
    if system == "darwin":
        if machine in ("x86_64", "amd64"):
            return "x86_64-apple-darwin"
        if machine in ("arm64", "aarch64"):
            return "aarch64-apple-darwin"
    if system in ("windows", "msys", "cygwin"):
        if machine in ("x86_64", "amd64"):
            return "x86_64-pc-windows-msvc"
    raise RuntimeError(f"unsupported platform for delta: {system} {machine}")


def ensure_delta_config(root):
    compare_dir = root / "build" / "glossary-compare"
    compare_dir.mkdir(parents=True, exist_ok=True)
    config_path = compare_dir / "delta.conf"
    if config_path.is_file():
        return config_path

    delta_section = extract_delta_config(Path.home() / ".gitconfig")
    if delta_section:
        content = delta_section
    else:
        content = DEFAULT_DELTA_CONFIG.strip()
    config_path.write_text(content + "\n", encoding="utf-8")
    return config_path


def extract_delta_config(path):
    if not path.is_file():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    sections = []
    current = []
    in_delta = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_delta and current:
                sections.append("\n".join(current))
            in_delta = stripped.startswith("[delta")
            current = [line] if in_delta else []
            continue
        if in_delta:
            current.append(line)
    if in_delta and current:
        sections.append("\n".join(current))
    return "\n\n".join(section for section in sections if section).strip()


def current_git_commit(root):
    try:
        return (
            subprocess.run(
                ["git", "rev-parse", "HEAD"],
                check=True,
                stdout=subprocess.PIPE,
            )
            .stdout.decode("utf-8")
            .strip()
        )
    # `git` executable missing from the system
    except FileNotFoundError:
        print("warning: failed to detect git commit: missing executable git")
        return
    # `git` returned an error (git will print the actual error to stderr)
    except subprocess.CalledProcessError:
        print("warning: failed to detect git commit: git returned an error")
        return


def main(root):
    root = Path(root)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--clear", help="disable incremental builds", action="store_true"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-s",
        "--serve",
        help="start a local server with live reload",
        action="store_true",
    )
    group.add_argument(
        "--check-links", help="Check whether all links are valid", action="store_true"
    )
    group.add_argument(
        "--xml", help="Generate Sphinx XML rather than HTML", action="store_true"
    )
    group.add_argument(
        "--check-generated-glossary",
        help="Compare generated glossary output",
        action="store_true",
    )
    parser.add_argument(
        "--debug",
        help=(
            "Debug mode for the extensions, showing exceptions "
            "(not compatible with --serve)"
        ),
        action="store_true",
    )
    args = parser.parse_args()

    if args.debug and args.serve:
        parser.error("--debug is not compatible with --serve")

    if args.check_generated_glossary:
        check_generated_glossary(root, args.debug, args.clear)
        return

    rendered = build_docs(
        root,
        "xml" if args.xml else "html",
        args.clear,
        args.serve,
        args.debug,
    )

    if args.check_links:
        linkchecker = build_linkchecker(root)
        if subprocess.run([linkchecker, rendered]).returncode != 0:
            print("error: linkchecker failed")
            exit(1)


main(os.path.abspath(os.path.dirname(__file__)))

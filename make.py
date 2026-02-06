#!/usr/bin/env -S uv run
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers
# SPDX-FileCopyrightText: The Rust Project Contributors

import os
import sys
from pathlib import Path
import argparse
import subprocess
import shutil

# Automatically watch the following extra directories when --serve is used.
EXTRA_WATCH_DIRS = ["exts", "themes"]


def run_changelog_assistant(root, update, require_tags):
    command = [sys.executable, str(root / "tools" / "changelog_assistant.py")]
    command.append("--update" if update else "--check")
    if require_tags:
        command.append("--require-tags")
    subprocess.run(command, check=True)


def build_docs(
    root,
    builder,
    clear,
    serve,
    debug,
    check_changelog,
    update_changelog,
    changelog_require_tags,
):
    dest = root / "build"
    output_dir = dest / builder

    args = ["-b", builder, "-d", dest / "doctrees"]
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

    should_run_changelog = check_changelog or update_changelog or (serve and not update_changelog)
    if should_run_changelog:
        run_changelog_assistant(
            root,
            update=update_changelog,
            require_tags=changelog_require_tags,
        )

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
        "--debug",
        help="Debug mode for the extensions, showing exceptions",
        action="store_true",
    )
    parser.add_argument(
        "--check-changelog",
        help="run changelog assistant in check mode",
        action="store_true",
    )
    parser.add_argument(
        "--update-changelog",
        help="run changelog assistant in update mode",
        action="store_true",
    )
    parser.add_argument(
        "--changelog-require-tags",
        help="fail changelog check when entries miss Change tags",
        action="store_true",
    )
    args = parser.parse_args()

    rendered = build_docs(
        root,
        "xml" if args.xml else "html",
        args.clear,
        args.serve,
        args.debug,
        args.check_changelog,
        args.update_changelog,
        args.changelog_require_tags,
    )

    if args.check_links:
        linkchecker = build_linkchecker(root)
        if subprocess.run([linkchecker, rendered]).returncode != 0:
            print("error: linkchecker failed")
            exit(1)


main(os.path.abspath(os.path.dirname(__file__)))

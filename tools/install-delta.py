#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The Ferrocene Developers
# SPDX-FileCopyrightText: The Rust Project Contributors

import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile

DELTA_VERSION = "0.18.2"
RELEASES_URL = "https://api.github.com/repos/dandavison/delta/releases"
DEFAULT_DELTA_CONFIG = """[delta]
    syntax-theme = none
    line-numbers = false
    side-by-side = false
    navigate = false
"""


def main():
    root = Path(__file__).resolve().parent.parent
    target = delta_target()
    binary_name = "delta.exe" if platform.system().lower().startswith("win") else "delta"

    install_dir = root / ".cache" / "delta" / DELTA_VERSION / target
    install_dir.mkdir(parents=True, exist_ok=True)
    binary_path = install_dir / binary_name

    if not binary_path.exists():
        download_delta(binary_path, target)

    ensure_delta_config(root)
    check_version_lag()

    print(f"installed delta at {binary_path}")


def download_delta(binary_path, target):
    archive_name = delta_archive_name(target)
    archive_path = binary_path.parent / archive_name
    url = download_url(archive_name)
    download_file(url, archive_path)
    extract_archive(archive_path, binary_path)
    archive_path.unlink(missing_ok=True)


def delta_archive_name(target):
    extension = ".zip" if platform.system().lower().startswith("win") else ".tar.gz"
    return f"delta-{DELTA_VERSION}-{target}{extension}"


def download_url(archive_name):
    for tag in (DELTA_VERSION, f"v{DELTA_VERSION}"):
        url = (
            "https://github.com/dandavison/delta/releases/download/"
            f"{tag}/{archive_name}"
        )
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "fls-glossary-auto-generation"},
            )
            with urllib.request.urlopen(request):
                return url
        except urllib.error.HTTPError:
            continue
    raise RuntimeError(f"unable to locate delta {DELTA_VERSION} release asset")


def download_file(url, destination):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "fls-glossary-auto-generation"},
    )
    with urllib.request.urlopen(request) as response, open(destination, "wb") as handle:
        shutil.copyfileobj(response, handle)


def extract_archive(archive_path, binary_path):
    temp_dir = binary_path.parent / "tmp"
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True, exist_ok=True)

    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(temp_dir)
    else:
        with tarfile.open(archive_path) as archive:
            archive.extractall(temp_dir)

    extracted = next(temp_dir.rglob(binary_path.name), None)
    if extracted is None:
        raise RuntimeError("delta binary not found in release archive")

    shutil.move(str(extracted), binary_path)
    shutil.rmtree(temp_dir)

    if not platform.system().lower().startswith("win"):
        os.chmod(binary_path, 0o755)


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


def check_version_lag():
    try:
        request = urllib.request.Request(
            RELEASES_URL,
            headers={"User-Agent": "fls-glossary-auto-generation"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        print(f"warning: failed to check delta releases: {exc}", file=sys.stderr)
        return

    releases = [
        release.get("tag_name", "").lstrip("v")
        for release in data
        if not release.get("prerelease")
    ]
    if not releases or DELTA_VERSION not in releases:
        return
    index = releases.index(DELTA_VERSION)
    if index >= 2:
        print(
            f"warning: delta {DELTA_VERSION} is {index} releases behind {releases[0]}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()

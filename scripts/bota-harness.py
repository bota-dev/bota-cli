#!/usr/bin/env python3
"""Install and check Bota's shared engineering instructions using Python 3.11+."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

SOURCE_REPOSITORY = "bota-dev/claude-code-plugins"
BUNDLE_PATH = "engineering-harness/bundle"
SKILL_ROOT = "plugins/bota-skills/skills"
SELECTED_SKILLS = ("compound-engineering", "bota-code-change", "bota-review-change")
LOCK_PATH = "harness.lock.json"
LOCAL_PATH = ".bota-harness/repo.md"
COMMON_PATH = ".bota-harness/common.md"
SCRIPT_PATH = "scripts/bota-harness.py"
WORKFLOWS = {"bota-harness.yml", "bota-harness-update.yml"}


class HarnessError(Exception):
    pass


def digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def target_path(source: str) -> str:
    parts = PurePosixPath(source).parts
    if (not parts or source != "/".join(parts) or ".." in parts
            or not re.fullmatch(r"[A-Za-z0-9_./-]+", source) or source.startswith("/")):
        raise HarnessError(f"Invalid bundle path: {source!r}")
    if source == "rules.md":
        return COMMON_PATH
    if source == "harness.py":
        return SCRIPT_PATH
    if len(parts) == 2 and parts[0] == "workflows" and parts[1] in WORKFLOWS:
        return ".github/workflows/" + parts[1]
    if len(parts) >= 3 and parts[0] == "skills" and (re.fullmatch(r"bota-[a-z0-9-]+", parts[1]) or parts[1] == "compound-engineering"):
        return ".agents/" + source
    raise HarnessError(f"Unsupported bundle path: {source}")


def safe_path(repo: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    if not parts or relative != "/".join(parts) or relative.startswith("/") or ".." in parts:
        raise HarnessError(f"Invalid repository path: {relative!r}")
    path = repo
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise HarnessError(f"Refusing symlink: {relative}")
    return path


def read_text(path: Path) -> str:
    try:
        # Universal newlines keep text checks portable across Git checkouts.
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise HarnessError(f"Cannot read {path.name}: {type(exc).__name__}") from exc


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".bota-harness-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def git(source: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(source), *args], capture_output=True)
    if result.returncode:
        # Avoid echoing credential-bearing remote URLs from Git diagnostics.
        raise HarnessError(f"Git {args[0]} failed; check the source checkout and ref")
    return result.stdout


def load_source(source: Path, ref: str = "HEAD") -> tuple[dict, dict[str, str]]:
    commit = git(source, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise HarnessError("Source must resolve to a full Git commit SHA")
    origin = git(source, "remote", "get-url", "origin").decode().strip()
    expected = {f"https://github.com/{SOURCE_REPOSITORY}.git", f"https://github.com/{SOURCE_REPOSITORY}",
                f"git@github.com:{SOURCE_REPOSITORY}.git", f"ssh://git@github.com/{SOURCE_REPOSITORY}.git"}
    if origin not in expected:
        raise HarnessError(f"Source origin must identify {SOURCE_REPOSITORY}")
    files = {}

    def collect(source_path: str, prefix: str = "") -> None:
        for entry in git(source, "ls-tree", "-r", "-z", f"{commit}:{source_path}").split(b"\0"):
            if not entry:
                continue
            meta, raw_path = entry.split(b"\t", 1)
            mode, kind, _sha = meta.split()
            path = raw_path.decode("utf-8")
            key = prefix + path
            target_path(key)
            if mode not in {b"100644", b"100755"} or kind != b"blob":
                raise HarnessError(f"Source requires regular files: {key}")
            try:
                files[key] = git(source, "show", f"{commit}:{source_path}/{path}").decode("utf-8").replace("\r\n", "\n")
            except UnicodeError as exc:
                raise HarnessError(f"Source requires UTF-8 text: {key}") from exc

    collect(BUNDLE_PATH)
    if any(path.startswith("skills/") for path in files):
        raise HarnessError("Keep canonical skills under plugins/bota-skills/skills, not in the bundle")
    for name in SELECTED_SKILLS:
        collect(f"{SKILL_ROOT}/{name}", f"skills/{name}/")
    required = ({"rules.md", "harness.py"}
                | {f"workflows/{name}" for name in WORKFLOWS}
                | {f"skills/{name}/SKILL.md" for name in SELECTED_SKILLS})
    if not required <= files.keys():
        raise HarnessError("Source bundle is incomplete")
    return {"repository": SOURCE_REPOSITORY, "commit": commit, "path": BUNDLE_PATH,
            "skills_path": SKILL_ROOT}, files



def load_lock(repo: Path) -> dict:
    try:
        lock = json.loads(read_text(safe_path(repo, LOCK_PATH)))
        if lock["schema_version"] != 1 or lock["source"]["repository"] != SOURCE_REPOSITORY:
            raise ValueError("unsupported source or schema")
        if (lock["source"]["path"] != BUNDLE_PATH or lock["source"].get("skills_path") != SKILL_ROOT) or not re.fullmatch(r"[0-9a-f]{40}", lock["source"]["commit"]):
            raise ValueError("invalid source pin")
        seen = set()
        for item in lock["files"]:
            if item["target"] != target_path(item["source"]) or item["target"] in seen:
                raise ValueError("invalid or duplicate target")
            seen.add(item["target"])
            if not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
                raise ValueError("invalid digest")
        required = {COMMON_PATH, SCRIPT_PATH} | {f".github/workflows/{name}" for name in WORKFLOWS}
        if not required <= seen or not re.fullmatch(r"[0-9a-f]{64}", lock["agents_sha256"]):
            raise ValueError("incomplete manifest")
        return lock
    except (KeyError, TypeError, ValueError) as exc:
        raise HarnessError("Invalid harness.lock.json") from exc


def verify_managed(repo: Path, lock: dict) -> None:
    targets = {item["target"] for item in lock["files"]}
    for item in lock["files"]:
        path = safe_path(repo, item["target"])
        if not path.is_file() or digest(read_text(path)) != item["sha256"]:
            raise HarnessError(f"Shared file drift: {item['target']}; restore it or update from the source repository")
    roots = {"/".join(path.split("/")[:3]) for path in targets if path.startswith(".agents/skills/")}
    for root in roots:
        for path in safe_path(repo, root).rglob("*"):
            relative = path.relative_to(repo).as_posix()
            safe_path(repo, relative)
            if path.is_file() and relative not in targets:
                raise HarnessError(f"Unmanaged file in shared skill: {relative}; use a separate repository skill")


def render_agents(repo: Path, source: dict) -> str:
    common = read_text(safe_path(repo, COMMON_PATH)).strip()
    local = read_text(safe_path(repo, LOCAL_PATH)).strip()
    return ("<!-- Generated by Bota harness. Edit .bota-harness/repo.md for repository guidance. -->\n"
            f"<!-- Source: {source['repository']}@{source['commit']} -->\n"
            "# Bota engineering instructions\n\n" + common
            + "\n\n## Repository guidance\n\n" + local + "\n")


def save_lock(repo: Path, lock: dict) -> None:
    write_text(safe_path(repo, LOCK_PATH), json.dumps(lock, indent=2, sort_keys=True) + "\n")


def render(repo: Path) -> None:
    lock = load_lock(repo)
    verify_managed(repo, lock)
    agents = safe_path(repo, "AGENTS.md")
    if not agents.is_file() or digest(read_text(agents)) != lock["agents_sha256"]:
        raise HarnessError("AGENTS.md was edited directly; move intended edits to .bota-harness/repo.md and restore the generated file")
    content = render_agents(repo, lock["source"])
    write_text(agents, content)
    lock["agents_sha256"] = digest(content)
    save_lock(repo, lock)


def check(repo: Path, source: Path | None = None) -> dict:
    lock = load_lock(repo)
    verify_managed(repo, lock)
    actual = read_text(safe_path(repo, "AGENTS.md"))
    if actual != render_agents(repo, lock["source"]) or digest(actual) != lock["agents_sha256"]:
        raise HarnessError("Generated AGENTS.md is stale; run python3 scripts/bota-harness.py render")
    if source is not None:
        metadata, files = load_source(source, lock["source"]["commit"])
        expected = {item["source"]: item["sha256"] for item in lock["files"]}
        if metadata != lock["source"] or {key: digest(value) for key, value in files.items()} != expected:
            raise HarnessError("Installed bundle differs from its pinned upstream commit")
    return {"source_commit": lock["source"]["commit"], "managed_files": len(lock["files"])}


def install(repo: Path, source: dict, files: dict[str, str], initialize: bool = False) -> dict:
    repo = repo.resolve()
    if not repo.is_dir():
        raise HarnessError("Target repository directory must already exist")
    if (source.get("repository") != SOURCE_REPOSITORY or source.get("path") != BUNDLE_PATH
            or source.get("skills_path") != SKILL_ROOT
            or not re.fullmatch(r"[0-9a-f]{40}", source.get("commit", ""))):
        raise HarnessError("Installation requires a valid source and full commit SHA")
    lock_path = safe_path(repo, LOCK_PATH)
    old = load_lock(repo) if lock_path.exists() else None
    if initialize == (old is not None):
        raise HarnessError("Use init for a new consumer and sync for an installed consumer")
    if old:
        verify_managed(repo, old)
        if digest(read_text(safe_path(repo, "AGENTS.md"))) != old["agents_sha256"]:
            raise HarnessError("AGENTS.md was edited directly; preserve intended edits in .bota-harness/repo.md first")
    targets = {target_path(key): value for key, value in files.items()}
    required = {COMMON_PATH, SCRIPT_PATH} | {f".github/workflows/{name}" for name in WORKFLOWS}
    if not required <= targets.keys():
        raise HarnessError("Source bundle is incomplete")
    old_targets = {item["target"] for item in old["files"]} if old else set()
    local_path = safe_path(repo, LOCAL_PATH)
    agents_path = safe_path(repo, "AGENTS.md")
    if old and not local_path.is_file():
        raise HarnessError("Repository guidance is missing")
    if not old and local_path.exists() and agents_path.exists():
        raise HarnessError("Both AGENTS.md and repository guidance exist; reconcile them before init")
    # Complete collision and symlink checks before changing the checkout.
    for relative in targets:
        path = safe_path(repo, relative)
        if path.exists() and relative not in old_targets:
            raise HarnessError(f"Existing file would be overwritten: {relative}")
    for root in {"/".join(p.split("/")[:3]) for p in targets if p.startswith(".agents/skills/")}:
        directory = safe_path(repo, root)
        if directory.exists():
            for path in directory.rglob("*"):
                relative = path.relative_to(repo).as_posix()
                safe_path(repo, relative)
                if path.is_file() and relative not in old_targets:
                    raise HarnessError(f"Existing skill file would be overwritten: {relative}")
    if not local_path.exists():
        guidance = read_text(agents_path) if agents_path.exists() else (
            "Record this repository's setup, build and test commands here.\n"
            "Preserve existing release, compatibility and deployment requirements.\n")
        write_text(local_path, guidance)
    for relative, content in targets.items():
        write_text(safe_path(repo, relative), content)
    for relative in sorted(old_targets - targets.keys()):
        safe_path(repo, relative).unlink()
    lock = {"schema_version": 1, "source": source,
            "files": [{"source": key, "target": target_path(key), "sha256": digest(value)}
                      for key, value in sorted(files.items())]}
    agents = render_agents(repo, source)
    lock["agents_sha256"] = digest(agents)
    write_text(agents_path, agents)
    save_lock(repo, lock)
    return check(repo)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["init", "sync", "check", "render"])
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--source", type=Path, help="Local checkout of bota-dev/claude-code-plugins")
    parser.add_argument("--ref", default="HEAD", help="Source ref to resolve and pin, for init/sync")
    args = parser.parse_args(argv)
    try:
        repo = args.repo.resolve()
        if args.command in {"init", "sync"}:
            if args.source is None:
                raise HarnessError("init/sync require --source pointing to a source checkout")
            metadata, files = load_source(args.source.resolve(), args.ref)
            result = install(repo, metadata, files, initialize=args.command == "init")
        elif args.command == "render":
            render(repo)
            result = check(repo)
        else:
            result = check(repo, args.source.resolve() if args.source else None)
        print(json.dumps({"status": "ok", "command": args.command, **result}, sort_keys=True))
        return 0
    except (HarnessError, OSError, UnicodeError) as exc:
        print(f"Bota harness: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

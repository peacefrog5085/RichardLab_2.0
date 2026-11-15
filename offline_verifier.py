"""Build and verify SHA-256 manifests for local evidence files."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

CHUNK_SIZE = 1024 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
COMPONENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_. -]*")
DEVICE = re.compile(r"CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9]", re.IGNORECASE)
DIGEST = re.compile(r"[0-9a-f]{64}")


class UnsafeFile(ValueError):
    """An evidence path does not name a regular file confined to the root."""


def _check_path(value):
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError("Invalid evidence path")
    for part in value.split("/"):
        if (not COMPONENT.fullmatch(part) or part.endswith((".", " "))
                or DEVICE.fullmatch(part.split(".", 1)[0].rstrip())):
            raise ValueError("Invalid evidence path")
    return value


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _root(path):
    root = Path(path).resolve(strict=True)
    if not root.is_dir():
        raise UnsafeFile("Evidence root must be a directory")
    return root


def _hash_file(root, relative):
    parts = relative.split("/")
    path = root
    for index, part in enumerate(parts):
        path = path / part
        info = path.lstat()
        reparse = getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        expected = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
        if reparse or not expected(info.st_mode):
            raise UnsafeFile("Evidence must use regular files and directories")
    if not path.resolve(strict=True).is_relative_to(root):
        raise UnsafeFile("Evidence path escapes the root")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as evidence:
        opened = os.fstat(evidence.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(info, opened):
            raise UnsafeFile("Evidence changed during open")
        digest = hashlib.sha256()
        for chunk in iter(lambda: evidence.read(CHUNK_SIZE), b""):
            digest.update(chunk)
        after = os.fstat(evidence.fileno())
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise UnsafeFile("Evidence changed during hashing")
    return digest.hexdigest()


def _validate_paths(paths):
    checked = [_check_path(path) for path in paths]
    if not checked or len({path.lower() for path in checked}) != len(checked):
        raise ValueError("Empty or duplicate evidence paths")
    return checked


def build_manifest(root, paths):
    """Return a canonical manifest for paths relative to the evidence root."""
    checked = _validate_paths(paths)
    root = _root(root)
    manifest = _json({"version": 1, "entries": [
        {"path": path, "sha256": _hash_file(root, path)} for path in sorted(checked)
    ]})
    if len(manifest) > MAX_MANIFEST:
        raise ValueError("Manifest too large")
    return manifest


def _load_manifest(raw):
    if len(raw) > MAX_MANIFEST:
        raise ValueError("Manifest too large")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    if (not isinstance(value, dict) or value.keys() != {"version", "entries"}
            or type(value["version"]) is not int or value["version"] != 1
            or not isinstance(value["entries"], list)):
        raise ValueError("Invalid manifest structure")
    entries = value["entries"]
    for entry in entries:
        if (not isinstance(entry, dict) or entry.keys() != {"path", "sha256"}
                or not isinstance(entry["sha256"], str) or not DIGEST.fullmatch(entry["sha256"])):
            raise ValueError("Invalid manifest entry")
    _validate_paths(entry["path"] for entry in entries)
    return sorted(entries, key=lambda entry: entry["path"])


def _error(code, path=None):
    return {"path": path, "status": "ERROR", "code": code}


def _write_stdout(value):
    sys.stdout.buffer.write(value.encode("utf-8"))


def verify_manifest(root, raw):
    """Return deterministic results without modifying or executing evidence."""
    try:
        entries = _load_manifest(raw)
    except (ValueError, TypeError, RecursionError):
        return {"results": [_error("INVALID_MANIFEST")]}
    try:
        root = _root(root)
    except (OSError, UnsafeFile, RuntimeError):
        return {"results": [_error("INVALID_ROOT")]}
    results = []
    for entry in entries:
        path = entry["path"]
        try:
            actual = _hash_file(root, path)
        except FileNotFoundError:
            results.append(_error("MISSING_FILE", path))
        except UnsafeFile:
            results.append(_error("UNSAFE_FILE", path))
        except (OSError, RuntimeError):
            results.append(_error("READ_ERROR", path))
        else:
            status = "MATCH" if actual == entry["sha256"] else "MISMATCH"
            results.append({"path": path, "status": status})
    return {"results": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("root")
    build.add_argument("paths", nargs="+")
    verify = commands.add_parser("verify")
    verify.add_argument("root")
    verify.add_argument("manifest")
    args = parser.parse_args()
    if args.command == "build":
        try:
            manifest = build_manifest(args.root, args.paths)
        except (OSError, ValueError, RuntimeError):
            _write_stdout(_json({"results": [_error("BUILD_ERROR")]}))
            return 2
        _write_stdout(manifest)
        return 0
    try:
        with open(args.manifest, "rb") as stream:
            report = verify_manifest(args.root, stream.read(MAX_MANIFEST + 1))
    except OSError:
        report = {"results": [_error("MANIFEST_READ_ERROR")]}
    _write_stdout(_json(report))
    statuses = {result["status"] for result in report["results"]}
    if "ERROR" in statuses:
        return 2
    return int("MISMATCH" in statuses)


if __name__ == "__main__":
    raise SystemExit(main())

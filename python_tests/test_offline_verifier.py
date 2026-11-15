import hashlib
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from offline_verifier import build_manifest, verify_manifest


class OfflineVerifierTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "sample.txt").write_bytes(b"synthetic\n")
        (self.root / "second.txt").write_bytes(b"second\n")

    def manifest(self):
        return build_manifest(self.root, ["sample.txt"])

    def verify(self, manifest):
        return verify_manifest(self.root, manifest)["results"]

    def test_valid_evidence(self):
        self.assertEqual(self.verify(self.manifest()), [
            {"path": "sample.txt", "status": "MATCH"},
        ])

    def test_one_byte_tampering(self):
        manifest = self.manifest()
        (self.root / "sample.txt").write_bytes(b"Synthetic\n")
        self.assertEqual(self.verify(manifest)[0]["status"], "MISMATCH")

    def test_missing_file(self):
        manifest = self.manifest()
        (self.root / "sample.txt").unlink()
        self.assertEqual(self.verify(manifest)[0]["code"], "MISSING_FILE")

    def test_invalid_hash(self):
        manifest = json.loads(self.manifest())
        manifest["entries"][0]["sha256"] = "not-a-hash"
        self.assertEqual(self.verify(json.dumps(manifest))[0]["code"], "INVALID_MANIFEST")

    def test_malformed_manifests(self):
        for manifest in ("{", "[]", '{"version": 1, "version": 1, "entries": []}'):
            with self.subTest(manifest=manifest):
                self.assertEqual(self.verify(manifest)[0]["status"], "ERROR")

    def test_duplicate_paths(self):
        manifest = json.loads(self.manifest())
        manifest["entries"].append(manifest["entries"][0])
        self.assertEqual(self.verify(json.dumps(manifest))[0]["code"], "INVALID_MANIFEST")
        with self.assertRaises(ValueError):
            build_manifest(self.root, ["sample.txt", "SAMPLE.txt"])

    def test_unsafe_paths(self):
        for path in ("../sample.txt", "/sample.txt", "x//sample.txt", "x/./sample.txt",
                     r"C:\sample.txt", r"x\..\sample.txt", "sample.txt:stream", "NUL.txt"):
            with self.subTest(path=path):
                manifest = json.loads(self.manifest())
                manifest["entries"][0]["path"] = path
                self.assertEqual(self.verify(json.dumps(manifest))[0]["code"], "INVALID_MANIFEST")
                with self.assertRaises(ValueError):
                    build_manifest(self.root, [path])

    def test_deterministic_manifest(self):
        first = build_manifest(self.root, ["sample.txt", "second.txt"])
        self.assertEqual(first, build_manifest(self.root, ["second.txt", "sample.txt"]))
        self.assertEqual(json.loads(first)["entries"][0]["sha256"],
                         hashlib.sha256(b"synthetic\n").hexdigest())
        self.assertTrue(first.endswith("\n"))

    def test_symlink_escape(self):
        manifest = self.manifest()
        (self.root / "sample.txt").unlink()
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "sample.txt"
            target.write_bytes(b"synthetic\n")
            try:
                (self.root / "sample.txt").symlink_to(target)
            except OSError as error:
                if sys.platform == "win32" and getattr(error, "winerror", None) == 1314:
                    self.skipTest("Windows symlink privilege is unavailable")
                raise
            self.assertEqual(self.verify(manifest)[0]["code"], "UNSAFE_FILE")

    def test_rejects_link_and_reparse_metadata_before_open(self):
        manifest = self.manifest()
        original = Path.lstat
        for mode, attributes in ((stat.S_IFLNK, 0),
                                 (stat.S_IFREG, stat.FILE_ATTRIBUTE_REPARSE_POINT)):
            with self.subTest(mode=mode, attributes=attributes):
                def lstat(path, *args, **kwargs):
                    if path.name == "sample.txt":
                        return SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
                    return original(path, *args, **kwargs)

                with patch.object(Path, "lstat", lstat), patch("offline_verifier.os.open") as opened:
                    self.assertEqual(self.verify(manifest)[0]["code"], "UNSAFE_FILE")
                    opened.assert_not_called()

    def test_streams_multiple_chunks(self):
        payload = b"a" * (2 * 1024 * 1024 + 5)
        (self.root / "sample.txt").write_bytes(payload)
        self.assertEqual(json.loads(self.manifest())["entries"][0]["sha256"],
                         hashlib.sha256(payload).hexdigest())

    def test_cli_reports_statuses_and_preserves_manifest_bytes(self):
        script = Path(__file__).resolve().parents[1] / "offline_verifier.py"

        def run(command, *args):
            return subprocess.run([sys.executable, str(script), command, str(self.root), *args],
                                  capture_output=True, check=False)

        built = run("build", "sample.txt")
        self.assertEqual(built.returncode, 0)
        self.assertEqual(built.stdout, self.manifest().encode("utf-8"))
        manifest = self.root / "manifest.json"
        manifest.write_bytes(built.stdout)
        for state, code in (("MATCH", 0), ("MISMATCH", 1), ("ERROR", 2)):
            with self.subTest(state=state):
                result = run("verify", str(manifest))
                self.assertEqual(result.returncode, code)
                self.assertEqual(json.loads(result.stdout)["results"][0]["status"], state)
            if state == "MATCH":
                (self.root / "sample.txt").write_bytes(b"Synthetic\n")
            elif state == "MISMATCH":
                (self.root / "sample.txt").unlink()

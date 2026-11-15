# Offline evidence verifier

Requires Python 3.12 or later. The verifier uses the Python standard library and reads evidence as bytes in 1 MiB chunks.

From the repository root in PowerShell 7.4+ or a POSIX shell:

```text
python -B offline_verifier.py build fixtures trial.txt > evidence.manifest.json
python -B offline_verifier.py verify fixtures evidence.manifest.json
python -B -m unittest discover -s python_tests -v
```

The example uses the committed synthetic trial. A successful verification prints `{"results":[{"path":"trial.txt","status":"MATCH"}]}`. Exit codes are 0 for all matches, 1 for a digest mismatch without errors, and 2 for one or more errors. Errors include a stable code. A malformed manifest produces one manifest-level error before any evidence is read.

Version 1 stores a sorted list of relative paths and lowercase SHA-256 digests. Output uses UTF-8 and a single trailing LF. Paths use forward slashes, portable ASCII filename characters, and regular files under the selected evidence directory. The verifier rejects case-insensitive duplicates, reserved names, symlinks and Windows reparse points under the evidence root.

Keep the baseline manifest somewhere trusted. A match establishes consistency with that manifest. Authenticity, authorship, and a trusted timestamp require independent evidence. Use a stable operator-controlled evidence directory while hashing and reviewing. The tool checks file identity and metadata around hashing, but the evidence directory is not a filesystem isolation boundary against concurrent privileged edits.

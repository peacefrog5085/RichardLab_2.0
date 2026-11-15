# RichardLab 2.0

The first offline workflow ingests UTF-8 evidence, verifies a pinned packet, checks exact citations and renders a deterministic, read-only Mission Control report in JSON. It requires Node.js 24 and has no third-party runtime dependencies.

From the repository root in PowerShell:

```powershell
node --test
$packet = Join-Path ([System.IO.Path]::GetTempPath()) ("richardlab-" + [guid]::NewGuid() + ".packet.json")
node src/cli.mjs build fixtures/trial.json > $packet
$pin = (Get-FileHash -Algorithm SHA256 -LiteralPath $packet).Hash.ToLowerInvariant()
node src/cli.mjs inspect $packet $pin
node src/cli.mjs dashboard $packet $pin > mission-control.report.html
Remove-Item -LiteralPath $packet
```

Use PowerShell 7.4 or later for the byte-preserving redirection above. The report should show Sentinel passed, Echo matched the citation and Jester flagged a single declared origin. Exit 1 means Sentinel blocked inspection. Exit 2 indicates invalid arguments or a read or validation error. Preserve the expected SHA-256 separately in a trusted location when reviewing the packet later.

- Ingestion accepts up to 16 adjacent regular UTF-8 files, 128 KiB each. Ordinary evidence uses `.txt`. A source with `"kind": "web-response"` uses a `.json` snapshot and gets Sentinel's web checks in Mission Control. See `fixtures/web-investigation.json` for a full example. Build produces a private packet containing full source bytes, assertions and provenance declarations. Use an operator-controlled input directory.
- Sentinel validates the packet digest, schema, evidence digests, canonical Base64 and UTF-8 before claim analysis. Integrity depends on a trusted expected digest.
- A citation can optionally declare a `stance` of `supports`, `challenges`, or `context`. Echo displays the declaration only when the quotation matches uniquely. Jester flags a matched challenge and highlights claims with both supporting and challenging declarations. Reviewers supply these labels.
- After integrity checks, Sentinel flags common instruction-override phrases, cleartext HTTP links and URLs containing user information. These offline heuristics surface review leads and can miss variants or flag benign text. Reports include only source IDs and finding codes. The scanner never opens destinations or sends source text to a service.
- Echo 777 reports exact UTF-8 citation offsets. Jester flags missing or ambiguous matches, a single declared origin and duplicate source bytes. These checks establish traceability and surface review questions. Claim truth, provenance authenticity and source independence require human review.
- Mission Control emits evidence IDs, digests, citation statuses and findings. It omits local paths, source contents and claim text. IDs can still reveal case information, so keep reports local by default.
- Run `node src/cli.mjs provenance PACKET SHA256` for an internal provenance report with source IDs, byte counts, SHA-256 digests, and declared origins and revisions. Sentinel must pass integrity checks before the report displays source records. Keep this report local because provenance labels can disclose information about the case.
- Open mission-control.report.html in a browser to view the same results offline. The dashboard is a read-only file.
- To review up to 32 packets together, create an index JSON array of entries with `id`, `file`, and `sha256`. Use unique lowercase case IDs, adjacent filenames ending in `.packet.json`, and separately retained lowercase SHA-256 values. Run `node src/cli.mjs cases index.json > cases.report.html`. A blocked packet appears alongside the other cases and makes the command exit with status 1. An invalid index exits with status 2.
- Use `node src/cli.mjs web-review fixtures/web-response.json` to review a saved response. Supply a UTF-8 JSON object with a response URL in `url` and a string-valued `headers` object. Sentinel checks for HTTP, URL user information, missing HSTS on HTTPS, and missing CSP headers on declared HTML. Results contain a digest and finding codes. The checks use only the supplied snapshot and do not assess live behavior, certificate validity or the strength of header values.
- Use `"kind": "ai-controls"` in an investigation's source entry to review an adjacent JSON snapshot. See `fixtures/ai-investigation.json` and its source. Fill in the five booleans from the workflow's actual configuration. Sentinel reports missing evidence instruction boundaries, unrestricted tool access, external writes without human approval, and raw evidence sent to a provider. These findings describe declared controls. They provide no live verification of the model or provider.
- Live internet security assessment, AI-provider integration and signed provenance remain open.

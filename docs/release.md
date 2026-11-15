# RichardLab 2.0 release preparation

The proposed public distribution is a source archive for local use and an optional static demonstration generated from the committed synthetic trial. The local workflow requires Node.js 24. The public demonstration requires a static file host and contains no user uploads or backend.

## Candidate verification

1. Test an exact clean commit with `node --test`. Record its SHA, Node version and result. The suite covers 150 combinations of text encoding, citation state and source relationships, with an external and embedded digest tamper check for each combination. Separate tests cover CLI, reporting, Sentinel advisories and case isolation.
2. Verify the candidate on the Windows, Linux and macOS CI jobs. Check the intended GitHub destination and connected integrations before pushing an isolated branch or opening a draft PR.
3. From the candidate checkout, build the public demo into an empty staging folder with `node scripts/build-public-demo.mjs > STAGING/index.html` in PowerShell 7.4+ or a POSIX shell. The command verifies the reviewed synthetic packet digest and accepts no case arguments. Verify the command succeeded and the staging folder contains only index.html. The browser CI job exercises the passing, blocked, and multi-case reports at desktop and mobile Chromium viewport sizes using synthetic fixtures. Review the job on the candidate commit. Retain the exact candidate commit and SHA-256 of both the archive and index.html.
4. Review the exact public files. Publish only the reviewed source archive and, if approved, the generated synthetic HTML demo. Keep case indexes, investigator inputs, packets and real case reports outside the publication directory.
5. After explicit approvals for the relevant merge, release and deployment, verify the hosted demo anonymously. Confirm that it displays the synthetic case and that no packet or report from a real case is accessible. Preserve the previous deployed artifact for rollback and record the deployed artifact digest.

The CLI and HTML rendering are available locally. The graphical UI is read-only. Sentinel checks integrity and flags a defined set of text risks offline. Semantic claim verification, model-assisted security review and live provider assessments remain outside the candidate's verified capabilities.

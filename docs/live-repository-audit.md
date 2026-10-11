# A real repository dependency audit

The Live repo auditor reads actual dependency artifacts and calls public vulnerability APIs at run time. It supports this workspace or a public GitHub repository. There are no predefined findings, expected outcomes, synthetic targets or seeded advisories in this workflow.

## Use it

Open http://127.0.0.1:8000 and select **Live repo auditor**. Choose this workspace, or supply a GitHub `owner/repository`, branch/tag/commit and artifact paths separated by commas. Supported artifacts are pinned Python requirements/constraints `.txt` or `.lock` files and npm `package-lock.json` v2/v3. Start live audit. Unresolved ranges, included files and unsupported entries are reported rather than guessed.

The source is read without installing dependencies or executing repository code. A GitHub ref is resolved to its immutable commit; each artifact has a SHA-256 hash and source link. Only package identifiers and exact declared versions are queried against vulnerability databases.

Three separately addressed specialists participate over the actual configured transport:

1. **Dependency investigator** queries [OSV's version API](https://google.github.io/osv.dev/post-v1-querybatch/) and fetches matched advisory records.
2. **Advisory verifier** asks the [GitHub Advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories) whether the exact package versions are affected, and retains missing corroboration as unknown.
3. **Remediation reviewer** checks whether advisory-supplied fix boundaries correspond to published PyPI/npm releases, then queries OSV for a published candidate chosen from the highest parsed boundary in the detailed findings.

In model mode each specialist reviews the facts, then challenges the other specialists' interpretations. Initial and final positions remain in the exported event trace. Models may suggest priorities and next steps; they cannot change the observed package/version match status. In rule mode the labels identify policy reasoning.

## What the result means

**Affected version corroborated** means OSV matched the declared version and GitHub's version-filtered advisory endpoint returned the corresponding record. Both sources may share upstream advisory data: this is corroboration, not independent exploit reproduction. The artifact establishes a declared dependency, not that it is installed, reachable or vulnerable in the deployed application.

Advisory fix boundaries and published releases are inputs to remediation review. Different boundaries do not establish that no common upgrade exists. Candidate-version queries are actual observations; zero returned matches still does not establish compatibility or absence of unknown flaws. They are not an automatically safe or compatible upgrade recommendation. Applicable branches, other advisories and dependency constraints still need testing. This workflow does not modify code or run exploits.

A completed query with no matches is labeled **No known advisory matches returned in the checked scope**, never “safe.” Failed source or OSV requests fail the audit. Failed GitHub corroboration leaves the corresponding findings requiring review. Registry failures remain unknown.

Limits: 500 unique package versions, eight detailed advisory hits, up to three OSV pagination rounds, 60 public HTTP requests, 2 MB per response, three artifacts and a 210-second overall deadline. Models review the first six detailed findings plus coverage totals. All returned package/advisory ID pairs are retained for export and source-link inspection, including records beyond the eight detailed reviews. The report records skipped entries, truncation and pagination coverage. Advisory hits can refer to overlapping aliases; do not interpret the count as unique CVEs. Conditional/dev dependencies are not deployment evidence.

## A reproducible public example

The form prefills `apache/airflow`, ref `constraints-2.6.0`, artifact `constraints-3.9.txt`. This is a genuine historical dependency snapshot published by the Apache project. It is useful for reproducing an audit against today's public advisory records. It does not assert that the current Airflow release uses these versions. Change the repository and ref to audit another actual artifact.

The other acceptance run audits this application's actual Python and npm lockfiles. Its findings are whatever the public APIs return; a zero-match outcome is valid.

Run the configured SLIM stack with `make model` or the ordinary Docker command in README. Then:

```sh
.venv/bin/python scripts/verify_repository_audit.py
```

This performs real public API requests and records both audits, source hashes, package versions, HTTP provenance, model calls, peer receipts and specialist positions in `docs/repository-audit-verification.json`. Only claim successful live acceptance if that report's `validated` field is true.

## Judge-facing pitch

“Give us an actual repository and a dependency file. One agent finds advisory matches, another checks the exact affected version, and a third examines published fix releases. They challenge each other's interpretations. We show what the records establish, what remains unknown, and the next action a maintainer should take. Every result links back to a specific repository commit and public advisory.”

If asked how it differs from a conventional scanner: “A conventional scanner is the appropriate baseline for dependency detection. Our contribution is the explicit verification and remediation discussion, with provenance and retained uncertainty. We have not established better detection accuracy than OSV-Scanner, Dependabot or pip-audit.”

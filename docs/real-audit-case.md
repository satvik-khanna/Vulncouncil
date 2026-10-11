# Executed case: auditing VulnCouncil's own dependencies

Use the **This workspace** source in Live repo auditor. It reads `requirements.lock` and `frontend/package-lock.json`, deduplicates exact package/version pins, and queries actual public databases. This is the application's real dependency inventory, not an invented target or seeded vulnerability.

The executed public-API audit captured a match for the declared transitive dependency **nltk 3.10.3**, advisory [GHSA-8mgp-746c-j5xp](https://github.com/advisories/GHSA-8mgp-746c-j5xp). The record concerns model-artifact file APIs bypassing path restrictions. OSV and GitHub corroborated the affected-version match.

This establishes a dependency advisory match. It does not establish that VulnCouncil calls the affected APIs, passes attacker-controlled file paths, or is exploitable in deployment. Model reviewers retain that uncertainty. The captured record supplied no parsed fix boundary; do not invent an upgrade version or interpret that as proof no fix exists anywhere. Source records can change: use the saved capture for reproduction and rerun the live audit to see current results.

The relevant triage decision is whether to investigate runtime use of the affected APIs, limit caller-controlled model paths, review upstream remediation and dependency constraints, or remove an unused dependency after compatibility testing. This auditor does not execute those changes.

## Pitch it

“We stopped demonstrating an invented vulnerable service and pointed the council at this application's actual lockfiles. It found a public advisory match in a transitive dependency. One specialist prioritizes the affected-version evidence, another verifies it, and the remediation specialist refuses to call it exploitable or invent a safe upgrade without evidence. These are real source records, a real dependency artifact, and a maintainer decision we can act on.”

Show the workspace audit, artifact hashes, advisory links, three final specialist positions and full initial/peer-review trace. Open the separate Airflow snapshot audit only to demonstrate larger-source coverage and candidate-version follow-up; label it historical. `docs/repository-audit-verification.json` contains executed observations and model metrics. The synthetic benchmark is not a measurement of this live auditor's accuracy.

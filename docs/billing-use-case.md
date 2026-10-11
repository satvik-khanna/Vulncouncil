# Customer isolation incident in a SaaS billing portal

VulnCouncil helps a security engineer establish whether a reported invoice leak is demonstrated, verify a tenant authorization fix, and preserve evidence that still needs incident review.

This is an executable local application with fictional companies, invoices and static demo credentials. The council sends authenticated HTTP GET requests to real FastAPI invoice handlers. Observations are computed from their responses; scenario configuration does not supply the verdict. This is not a production customer penetration test.

The defect matches [OWASP API1:2023 Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/): an authenticated caller requests an object without the server enforcing permission to that object.

## The incident

Alice belongs to Northstar. Bob and Beth belong to Harbor Robotics. Each credential maps to tenant membership on the server; sending another tenant header cannot change that membership.

The vulnerable deployment checks authentication and returns an invoice by ID, but omits the tenant check. Alice can retrieve Harbor's customer name, billing email, invoice amount and purchase-order reference. No payment credentials are included. The test does not establish fraud, the number of affected customers, or historical exfiltration.

The corrected deployment compares the invoice's tenant with the authenticated user's server-derived tenant. Beth must still be able to read Harbor's invoice even though she is not its creator. Blocking every request or enforcing an incorrect creator-only rule would fail the legitimate-access controls.

| HTTP observation | Vulnerable deployment | Corrected deployment |
| --- | --- | --- |
| Bob, Harbor owner | 200 with invoice | 200 with invoice |
| Beth, Harbor colleague | 200 with invoice | 200 with invoice |
| Alice, Northstar outsider | 200 with the same invoice | 403, no invoice |
| Missing or invalid authentication | 401 | 401 |

## What the council checks

Each approved invoice probe performs three HTTP reads: owner, colleague, outsider. A positive observation requires both legitimate controls to succeed and the outsider to receive the same invoice as the owner. A negative observation requires both legitimate controls to succeed and the outsider to receive 403. Failed controls or unexpected responses are incomplete evidence, never proof of a successful patch.

`cross_user_access` probes INV-2001; `access_reproduce` probes INV-2002. Another specialist independently tests a second object. The gateway authorizes and counts every individual HTTP request against the existing limits. Only four exact invoice routes are added to the allowlist; arbitrary invoice IDs and external destinations remain blocked.

The audit keeps identity and tenant labels, status codes, invoice IDs, exposed field names, response hashes and environment versions. Raw invoice bodies and bearer credentials are not persisted. Actual peer messages and model calls remain visible in the council timeline.

## Run it for judges

Open http://127.0.0.1:8000. Start the model stack with `make model` if needed.

1. Select **Billing portal · cross-tenant invoice leak**, guard off. Both legitimate controls return 200, and the outsider receives 200. Independent evidence supports **CONFIRMED**.
2. Run the same scenario with the guard enabled. Owner and colleague still receive 200; outsider receives 403. The current finding becomes **NOT_REPRODUCED**.
3. Select **Billing portal · patch during incident**. It starts against the vulnerable deployment and automatically switches to the corrected deployment after discovery. Fresh checks observe denial. The combined incident record becomes **DISPUTED** because it includes demonstrated earlier exposure and later denial. This status does not imply the current patch is broken; inspect versions and current observations.

The guard toggle selects between two explicit demo deployments. It does not edit code or deploy a production patch. Both implementations are inspectable in `lab_target/billing.py`.

For a three-minute presentation, run the third scenario live and use saved completed runs for the first two. Model runs can take roughly two minutes. Begin immediately and explain customer impact while agents work. State whether the banner shows model or policy reasoning.

## Reproduce independently

These credentials belong only to the fictional local demo:

```sh
curl -i -H 'Authorization: Bearer demo-alice-northstar' http://127.0.0.1:8001/demo/vulnerable/invoices/INV-2001
curl -i -H 'Authorization: Bearer demo-alice-northstar' http://127.0.0.1:8001/demo/patched/invoices/INV-2001
curl -i -H 'Authorization: Bearer demo-beth-harbor' http://127.0.0.1:8001/demo/patched/invoices/INV-2001
```

Run `.venv/bin/python scripts/verify_billing.py` against the SLIM stack to validate all three council outcomes, direct HTTP controls and actual request accounting. Its report is `docs/billing-verification.json`; claim successful live validation only when `validated` is true. The 13-case authored benchmark remains separate from this application acceptance test.

## Pitch

“Imagine a customer discovering another company's invoice in your billing portal. Our access specialist tests it, a skeptic reproduces it on another invoice, and the council records the evidence. We switch to the fixed API: the outsider is blocked, but legitimate colleagues still work. The agents reassess current exposure while the incident record preserves the leak already observed. A working patch is not a reason to erase an incident.”

If asked why multiple agents help: “Their checks and positions are independently auditable. Confirmation requires independent observations, and conflicting history stays visible. This demonstrates those behaviors; it does not establish that more agents always outperform one competent security engineer.”

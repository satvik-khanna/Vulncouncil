"""Executable demo billing API. All identities, companies and invoices are fictional."""
from fastapi import APIRouter, Header, HTTPException

router = APIRouter(prefix="/demo")
# Opaque demo credentials resolve to SERVER-owned tenant membership. A caller
# cannot select a tenant by sending a tenant ID in the request.
IDENTITIES = {
    "demo-alice-northstar": {"user": "alice", "tenant": "northstar"},
    "demo-bob-harbor": {"user": "bob", "tenant": "harbor"},
    "demo-beth-harbor": {"user": "beth", "tenant": "harbor"},
}
INVOICES = {
    "INV-2001": {"id": "INV-2001", "tenant": "harbor", "customer": "Harbor Robotics (fictional)", "billing_email": "billing@harbor.example", "amount_usd": 18420, "payment_reference": "DEMO-PO-701"},
    "INV-2002": {"id": "INV-2002", "tenant": "harbor", "customer": "Harbor Robotics (fictional)", "billing_email": "billing@harbor.example", "amount_usd": 7650, "payment_reference": "DEMO-PO-702"},
}


@router.get("/{deployment}/invoices/{invoice_id}")
def invoice(deployment: str, invoice_id: str, authorization: str | None = Header(default=None)):
    if deployment not in {"vulnerable", "patched"}:
        raise HTTPException(404, "Unknown demo deployment")
    identity = IDENTITIES.get((authorization or "").removeprefix("Bearer ")) if (authorization or "").startswith("Bearer ") else None
    if not identity:
        raise HTTPException(401, "Valid demo authentication required")
    record = INVOICES.get(invoice_id)
    if not record:
        raise HTTPException(404, "Invoice not found")
    # The vulnerable deployment authenticates the caller but omits this check.
    # The patch permits colleagues in the same tenant, not just the creator.
    if deployment == "patched" and record["tenant"] != identity["tenant"]:
        raise HTTPException(403, "Invoice belongs to another tenant")
    return record

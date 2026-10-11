from fastapi import FastAPI, HTTPException
from schemas.models import CheckRequest
from lab_target.scenarios import fixture_check
from lab_target.billing import router as billing_router

app = FastAPI(title="VulnCouncil synthetic fixture", docs_url=None, redoc_url=None)
app.include_router(billing_router)


@app.get("/health")
def health():
    return {"status": "ok", "synthetic": True}


@app.post("/checks")
def check(request: CheckRequest):
    try:
        return fixture_check(request.check, request.scenario, request.patched, request.variant)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


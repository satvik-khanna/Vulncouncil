"""Locked synthetic stress cases; separately executed, resource-measured baselines."""
import hashlib
import json
import math
import os
import time
from app.capability_discovery import ROOT
from schemas.models import AssessmentRequest

DATASET = ROOT / "config/evaluation_cases.json"
CASES = json.loads(DATASET.read_text())
MODES = ("single_agent", "simple_majority", "council")


def scores_for(rows):
    scores = {}
    for mode in MODES:
        tp = sum(r[mode] == "CONFIRMED" and r["label"] == "positive" for r in rows)
        fp = sum(r[mode] == "CONFIRMED" and r["label"] == "benign" for r in rows)
        fn = sum(r[mode] != "CONFIRMED" and r["label"] == "positive" for r in rows)
        correct = sum(r[mode] == r["expected"] for r in rows)
        n = len(rows)
        accuracy = correct / n
        # Wilson 95% interval expresses the uncertainty even with perfect cases.
        z = 1.96
        center = (accuracy + z*z/(2*n))/(1+z*z/n)
        margin = z*math.sqrt(accuracy*(1-accuracy)/n+z*z/(4*n*n))/(1+z*z/n)
        costs = [r["mode_metrics"][mode] for r in rows]
        scores[mode] = {"precision": tp/(tp+fp) if tp+fp else None,
            "recall": tp/(tp+fn) if tp+fn else None, "false_positives": fp,
            "unsupported_confirmations": sum(r[mode] == "CONFIRMED" and r["label"] == "abstain" for r in rows),
            "correct_abstentions": sum(r[mode] in {"NEEDS_HUMAN", "DISPUTED"} and r["label"] == "abstain" for r in rows),
            "abstention_cases": sum(r["label"] == "abstain" for r in rows),
            "exact_status_accuracy": accuracy, "accuracy_interval_95": [center-margin, center+margin],
            "cases": n, "tool_requests": sum(c["tool_requests"] for c in costs),
            "duration_seconds": round(sum(c["duration_seconds"] for c in costs), 3),
            "model_calls": sum(c["model_calls"] for c in costs), "model_tokens": sum(c["model_tokens"] for c in costs)}
    return scores


async def evaluate(service):
    if service.transport.mode != "memory":
        raise ValueError("Independent baselines currently require the explicitly labeled memory benchmark transport")
    rows = []
    started = time.monotonic()
    dataset_hash = hashlib.sha256(DATASET.read_bytes()).hexdigest()
    for index, case in enumerate(CASES):
        row = dict(case)
        row["mode_metrics"], row["run_ids"] = {}, {}
        # Rotate execution order to reduce a systematic warm-up advantage.
        order = MODES[index % 3:] + MODES[:index % 3]
        for mode in order:
            run = await service.open(AssessmentRequest(scenario=case["scenario"], patched=case["patched"]),
                background=False, fixture_variant=case.get("variant", "standard"), decision_mode=mode)
            if run.state == "failed":
                raise RuntimeError(f"Benchmark case {case['id']} mode {mode} failed: {run.error}")
            row[mode] = run.findings[0].status.value
            row["mode_metrics"][mode] = run.metrics.model_dump()
            row["run_ids"][mode] = run.run_id
        row["metrics"] = row["mode_metrics"]["council"]
        row["run_id"] = row["run_ids"]["council"]
        rows.append(row)
    model_enabled = getattr(service.transport, "allow_model", False) and os.getenv("AGENT_REASONING", "rules") == "llm"
    return {"transport": service.transport.mode, "reasoning": "llm" if model_enabled else "rules",
        "dataset_sha256": dataset_hash, "cases": rows, "scores": scores_for(rows),
        "split_scores": {split: scores_for([r for r in rows if r["split"] == split]) for split in ("development", "holdout")},
        "duration_seconds": round(time.monotonic()-started, 3),
        "belief_revisions": sum(r["metrics"]["belief_revisions"] for r in rows),
        "blocked_requests": sum(r["metrics"]["blocked_requests"] for r in rows),
        "evidence_coverage": sum(r["metrics"]["evidence_coverage"] for r in rows)/len(rows),
        "baseline_protocol": "Separate runs with the same fixture, specialist implementations, check permissions, 48-request budget and 120-second deadline. Single specialist performs all phases. Independent majority uses the initial relevant specialist, skeptic and risk assessor with only their own evidence and no peer delivery. Council shares evidence, recruits capabilities and applies deterministic adjudication. Additional council observations and cost are reported, so this is a system comparison rather than an isolated proof that dialogue helps.",
        "limitations": "13 authored synthetic conditions: 7 development and 6 reserved stress cases. Holdout labels/variants are never sent to models; cases are now public and must not be described as independently collected or permanently unseen. No real-world superiority claim. Rule-mode results do not validate LLM reasoning. Memory timings exclude SLIM overhead; model billing and token pricing are not estimated. Precision/recall use adjudicable positive/benign cases, not unknown truth in abstention cases. Confirmation on an abstention case is reported separately as unsupported confirmation. Precision/recall without a denominator are null. Intervals describe case-level accuracy uncertainty, not population validity."}

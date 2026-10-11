import asyncio
import logging
import os
import time
from collections import Counter
from typing import Callable

import yaml
from app.capability_discovery import CapabilityDiscovery, ROOT
from app.deliberation import resolve, majority
from app.safety_gate import SafetyBlocked
from app.storage import Storage
from app.telemetry import tracer
from schemas.models import AssessmentRequest, AssessmentRun, AgentMessage, EventType, Finding, Status, VoteChoice, now, uid
from tools.lab_client import LabClient
from tools.lab_gateway import LabToolGateway

logger = logging.getLogger("vulncouncil")


class RunService:
    def __init__(self, storage: Storage, registry: CapabilityDiscovery, lab_client: LabClient, delay: float = 0):
        self.storage = storage
        self.registry = registry
        self.lab_client = lab_client
        self.delay = delay
        self.transport = None
        self.runs: dict[str, AssessmentRun] = {}
        self.gateways: dict[str, LabToolGateway] = {}
        self.tasks: dict[str, asyncio.Task] = {}
        self.interventions_open: set[str] = set()
        self.scenarios = yaml.safe_load((ROOT / "config/scenarios.yaml").read_text())["scenarios"]

    def get(self, run_id):
        return self.runs.get(run_id) or self.storage.get(run_id)

    async def emit(self, run: AssessmentRun, message: AgentMessage):
        self.storage.event(message)
        logger.info("council_event run=%s agent=%s type=%s", run.run_id, message.agent_id, message.event_type)
        self.storage.save(run)
        if self.delay:
            await asyncio.sleep(self.delay)

    async def open(self, request: AssessmentRequest, background=True, *, fixture_variant="standard", decision_mode="council") -> AssessmentRun:
        if any(run.state in {"queued", "running"} for run in self.runs.values()):
            raise ValueError("An assessment is already active; stop it or wait for completion")
        if request.scenario in {"changing_access", "tenant_invoice_change"} and request.patched:
            raise ValueError("The surprise scenario requires the guard initially disabled")
        scenario_config = next(s for s in self.scenarios if s["id"] == request.scenario)
        required = {scenario_config["skill"]} if decision_mode == "single_agent" else {scenario_config["skill"], "verification", "risk"}
        missing = [skill for skill in required if not self.registry.select({skill})]
        if missing:
            raise ValueError(f"Required capabilities unavailable: {', '.join(sorted(missing))}")
        reasoning = os.getenv("AGENT_REASONING", "rules") if getattr(self.transport, "allow_model", True) else "rules"
        run = AssessmentRun(scenario=request.scenario, patched=request.patched or request.scenario == "patched_access", transport=self.transport.mode, fixture_variant=fixture_variant, decision_mode=decision_mode, reasoning=reasoning, reasoning_model=os.getenv("LLM_MODEL") if reasoning == "llm" else None)
        self.runs[run.run_id] = run
        self.storage.save(run)
        async def blocked(agent_id, reason):
            run.metrics.blocked_requests += 1
            await self.emit(run, AgentMessage(run_id=run.run_id, agent_id=agent_id, event_type=EventType.SAFETY_BLOCKED, claim=reason))
        self.gateways[run.run_id] = LabToolGateway(run, self.registry, self.lab_client, blocked)
        if background:
            self.tasks[run.run_id] = asyncio.create_task(self.execute(run))
        else:
            await self.execute(run)
        return run

    async def exchange(self, run, phase, context):
        with tracer.start_as_current_span("council.group_exchange", attributes={"run.id": run.run_id, "phase": phase, "transport": run.transport}):
            packets = await self.transport.exchange(phase, context, run.selected_agents)
        run.metrics.group_messages += 1 + len(packets)
        run.metrics.peer_receipts = sum(p.peer_receipts for p in packets)
        errors = [p.error for p in packets if p.error]
        if errors:
            if self.gateways[run.run_id].gate.stopped:
                raise SafetyBlocked("A specialist check was stopped by the shared safety gate")
            raise RuntimeError("; ".join(errors))
        requested = []
        for packet in packets:
            run.metrics.model_calls += packet.model_calls
            run.metrics.model_tokens += packet.model_tokens
            requested.extend((packet.agent_id, skill) for skill in packet.requested_skills)
            evidence_ids = {e.evidence_id for e in run.evidence}
            for item in packet.evidence:
                if item.evidence_id not in evidence_ids:
                    observed = next((e for e in self.gateways[run.run_id].evidence if e.evidence_id == item.evidence_id), None)
                    if observed is None or observed.agent_id != packet.agent_id or observed.model_dump(exclude={"decisive_counterexample"}) != item.model_dump(exclude={"decisive_counterexample"}):
                        raise RuntimeError("Agent evidence did not match a trusted gateway observation")
                    if item.decisive_counterexample:
                        signal = next((e.facts.get("signal") for e in run.evidence if e.tool_name == "injection_signal"), None)
                        if item.tool_name != "benign_control" or not signal or item.facts.get("signal") != signal:
                            raise RuntimeError("Counterexample was not grounded in the matched fixture control")
                    run.evidence.append(item)
                    evidence_ids.add(item.evidence_id)
            for finding in packet.findings:
                if run.scenario.startswith("tenant_invoice"):
                    finding.title = "Cross-tenant invoice disclosure"
                    finding.asset = "Fictional SaaS billing portal"
                    finding.route = "/demo/{deployment}/invoices/{invoice_id}"
                    finding.impact_band = "high"
                    finding.remediation = "Enforce server-derived tenant membership on every invoice read. Keep same-tenant colleague access working; retest both controls and cross-tenant reads. Review historical access separately from patch verification."
                    finding.limitations = ["Executable local billing API with fictional data and static demo credentials; not a production penetration test", "Two invoices tested; no claim about the number of customers affected or historical exfiltration"]
                if not any(f.finding_id == finding.finding_id for f in run.findings):
                    run.findings.append(finding)
            for event in packet.events:
                await self.emit(run, event)
        if run.decision_mode == "council":
            newcomers = []
            for agent_id, skill in dict.fromkeys(requested):
                matches = self.registry.select({skill})
                if not matches:
                    raise RuntimeError(f"Requested capability unavailable: {skill}")
                cap = matches[0]
                if cap.agent_id in run.selected_agents:
                    continue
                await self.emit(run, AgentMessage(run_id=run.run_id, agent_id=agent_id, event_type=EventType.COLLABORATOR_REQUESTED, claim=f"Request {skill} expertise to investigate the current evidence gap."))
                run.selected_agents.append(cap.agent_id)
                newcomers.append(cap.agent_id)
                await self.emit(run, AgentMessage(run_id=run.run_id, agent_id=cap.agent_id, event_type=EventType.CAPABILITY_SELECTED, claim=f"Recruited during {phase} by skill {skill}. Objective: {cap.objective}."))
            if newcomers:
                # Orientation may inspect context, but cannot recursively recruit.
                oriented = await self.transport.exchange("orient", self.context(run, context["category"], context["finding_id"], context.get("round", 1)), newcomers)
                for packet in oriented:
                    if packet.error:
                        raise RuntimeError(packet.error)
                    for item in packet.evidence:
                        trusted = next((e for e in self.gateways[run.run_id].evidence if e.evidence_id == item.evidence_id), None)
                        if trusted is None or item != trusted:
                            raise RuntimeError("Untrusted orientation evidence")
                        run.evidence.append(item)
                    for event in packet.events:
                        await self.emit(run, event)
                    run.metrics.model_calls += packet.model_calls
                    run.metrics.model_tokens += packet.model_tokens
        self.storage.save(run)
        return packets

    def context(self, run, category, finding_id, round=0):
        finding = next((f for f in run.findings if f.finding_id == finding_id), None)
        return {"run_id": run.run_id, "scenario": run.scenario, "patched": run.patched, "category": category,
                "authorization_policy": "Authenticated users may read invoices belonging to their server-assigned tenant, including colleagues' invoices. Cross-tenant reads must be denied. Test actual HTTP visibility, owner and same-tenant controls; a disabled guard does not grant permission." if run.scenario.startswith("tenant_invoice") else None,
                "finding_id": finding_id, "round": round, "evidence": [e.model_dump(mode="json") for e in run.evidence],
                "initial_confidence": finding.initial_confidence if finding else .6,
                "primary_agent": self.registry.select({{"injection": "injection", "broken_access_control": "access_control", "misconfiguration": "hardening"}[category]})[0].agent_id,
                "independent": run.decision_mode != "council",
                "available_skills": sorted({skill for a in self.registry.agents for skill in a.skills}),
                "positions": [e for e in self.storage.events(run.run_id) if e["confidence_after"] is not None],
                "peer_claims": [{k: e[k] for k in ("agent_id", "event_type", "claim", "evidence_ids")} for e in self.storage.events(run.run_id) if e["event_type"] in {"CHALLENGE", "BELIEF_UPDATED", "FINDING_PROPOSED"}],
                "environment_version": run.environment_version}

    async def execute(self, run: AssessmentRun):
        started = time.monotonic()
        run.state = "running"
        self.interventions_open.add(run.run_id)
        scenario = next(s for s in self.scenarios if s["id"] == run.scenario)
        category = {"injection": "injection", "access_control": "broken_access_control", "hardening": "misconfiguration"}[scenario["skill"]]
        primary = self.registry.select({scenario["skill"]})[0].agent_id
        finding_id = uid("finding")
        required = {scenario["skill"]} if run.decision_mode == "single_agent" else {scenario["skill"], "verification", "risk"}
        run.selected_agents = [a.agent_id for a in self.registry.select(required)]
        terminal_state = "failed"
        try:
            async with asyncio.timeout(self.gateways[run.run_id].gate.policy["deadline_seconds"]):
                opening = AgentMessage(run_id=run.run_id, agent_id="facilitator", event_type=EventType.ASSESSMENT_OPENED,
                    claim="Local billing API assessment opened with fictional tenants and invoices. Owner, colleague and cross-tenant HTTP reads test customer isolation." if run.scenario.startswith("tenant_invoice") else "Synthetic fixture assessment opened. Specialists decide their positions; deterministic evidence rules resolve the finding.",
                    data={"target": run.target_id, "scenario": run.scenario, "transport": run.transport, "limits": self.gateways[run.run_id].gate.policy})
                await self.emit(run, opening)
                selections = []
                for cap in self.registry.select(required):
                    event = AgentMessage(run_id=run.run_id, agent_id=cap.agent_id, event_type=EventType.CAPABILITY_SELECTED,
                        claim=f"Selected by declared capabilities {', '.join(cap.skills)}. Objective: {cap.objective}.")
                    selections.append(event.model_dump(mode="json"))
                    await self.emit(run, event)
                ctx = self.context(run, category, finding_id)
                ctx["broadcast_events"] = [opening.model_dump(mode="json"), *selections]
                await self.exchange(run, "observe", ctx)
                if run.scenario == "scope_violation":
                    await self.gateways[run.run_id].check(primary, "external_destination", finding_id)
                if run.patched and category == "broken_access_control":
                    previous = next((r for r in self.storage.list() if r["run_id"] != run.run_id and not r["patched"] and r["scenario"] == "access_control" and r["state"] == "completed"), None)
                    if previous and previous["findings"]:
                        ctx["prior_confidence"] = previous["findings"][0]["confidence"]
                        ctx["prior_run_id"] = previous["run_id"]
                discovery = await self.exchange(run, "discover", ctx)
                initial_votes = [v for packet in discovery for v in packet.votes]
                if not run.findings:
                    raise RuntimeError("No specialist proposed a finding")
                finding = run.findings[0]
                proposer_vote = next((v for v in initial_votes if v.agent_id == primary), None)
                finding.baseline = {"single_agent": (Status.CONFIRMED if proposer_vote and proposer_vote.vote == VoteChoice.CONFIRM else Status.DISPUTED).value,
                                    "simple_majority": majority(initial_votes).value}
                if run.scenario in {"changing_access", "tenant_invoice_change"} and not run.patched:
                    await self.intervene(run.run_id, "enable_guard")
                await self.exchange(run, "challenge", self.context(run, category, finding_id, 1))
                reviews = await self.exchange(run, "review", self.context(run, category, finding_id, 1))
                revisions = [e for p in reviews for e in p.events if e.event_type == EventType.BELIEF_UPDATED]
                primary_revision = next((e for e in revisions if e.agent_id == primary), None)
                if primary_revision:
                    finding.confidence = primary_revision.confidence_after
                run.metrics.belief_revisions = sum(bool(e.evidence_ids) and e.confidence_before != e.confidence_after for e in revisions)
                self.interventions_open.discard(run.run_id)
                voted = await self.exchange(run, "vote", self.context(run, category, finding_id, 2))
                finding.votes = [v for p in voted for v in p.votes]
                if os.getenv("AGENT_REASONING", "rules") == "llm":
                    latest_primary = next((v for v in finding.votes if v.agent_id == primary), None)
                    if latest_primary:
                        finding.confidence = latest_primary.confidence
                evidence = [e for e in run.evidence if e.finding_id == finding_id]
                finding.evidence_ids = [e.evidence_id for e in evidence]
                with tracer.start_as_current_span("council.adjudication", attributes={"run.id": run.run_id, "finding.id": finding_id}):
                    finding.status, finding.rule = resolve(evidence, finding.votes, self.gateways[run.run_id].gate.stopped)
                    if run.decision_mode == "council" and run.environment_version > 0 and not any(e.facts.get("environment_version") == run.environment_version and e.result in {"positive", "negative", "incomplete", "signal"} for e in evidence):
                        finding.status, finding.rule = Status.NEEDS_HUMAN, "STALE_EVIDENCE: environment changed without a subsequent observation"
                    if run.decision_mode != "council":
                        finding.status = majority(finding.votes)
                        finding.rule = "INDEPENDENT_FINAL_VOTE: same specialist policies and tool permissions, without peer evidence or council adjudication"
                finding.reproducible = any(e.result == "positive" and e.reproducible for e in evidence)
                finding.supporting_agents = [v.agent_id for v in finding.votes if v.vote == VoteChoice.CONFIRM]
                finding.challenging_agents = [v.agent_id for v in finding.votes if v.vote in {VoteChoice.REJECT, VoteChoice.DISPUTED}]
                resolved = AgentMessage(run_id=run.run_id, finding_id=finding_id, agent_id="evidence_protocol", event_type=EventType.FINDING_RESOLVED,
                    round=2, claim=f"{finding.status}: {finding.rule}", evidence_ids=finding.evidence_ids,
                    data={"status": finding.status, "rule": finding.rule, "tally": dict(Counter(v.vote for v in finding.votes))})
                await self.emit(run, resolved)
                await self.exchange(run, "observe", {**self.context(run, category, finding_id, 2), "broadcast_events": [resolved.model_dump(mode="json")]})
                terminal_state = "completed"
        except asyncio.CancelledError:
            terminal_state = "stopped"
            self.gateways[run.run_id].gate.stopped = True
            self.mark_human(run, finding_id, "USER_STOP: global stop switch activated")
            await self.emit(run, AgentMessage(run_id=run.run_id, agent_id="safety_gate", event_type=EventType.ASSESSMENT_STOPPED, claim="Run stopped. No further tools may execute."))
        except SafetyBlocked as exc:
            terminal_state = "stopped"
            self.mark_human(run, finding_id, f"SAFETY_STOP: {exc}")
        except TimeoutError:
            terminal_state = "stopped"
            self.gateways[run.run_id].gate.stopped = True
            self.mark_human(run, finding_id, "DEADLINE_STOP: bounded assessment deadline exceeded")
            await self.emit(run, AgentMessage(run_id=run.run_id, agent_id="safety_gate", event_type=EventType.SAFETY_BLOCKED, claim="Assessment deadline exceeded; seek human review."))
        except Exception as exc:
            logger.exception("Assessment failed run=%s", run.run_id)
            terminal_state = "failed"
            run.error = f"{type(exc).__name__}: {str(exc)[:240]}"
            self.gateways[run.run_id].gate.stopped = True
            self.mark_human(run, finding_id, "EXECUTION_FAILURE: missing evidence; inspect the actionable run error")
            await self.emit(run, AgentMessage(run_id=run.run_id, agent_id="facilitator", event_type=EventType.ERROR, claim=run.error))
        finally:
            self.interventions_open.discard(run.run_id)
            gate = self.gateways[run.run_id].gate
            run.metrics.tool_requests = sum(gate.counts.values())
            run.metrics.duration_seconds = round(time.monotonic() - started, 3)
            run.metrics.evidence_coverage = sum(bool(f.evidence_ids) for f in run.findings) / max(1, len(run.findings))
            final = AgentMessage(run_id=run.run_id, agent_id="facilitator", event_type=EventType.ASSESSMENT_COMPLETED,
                                 claim=f"Run {terminal_state}. Evidence and dissent retained. Synthetic fixture results do not establish real-world exploitability.", data=run.metrics.model_dump())
            # Final bookkeeping also traverses the real group; transport failure stays visible.
            if terminal_state == "completed":
                try:
                    await self.exchange(run, "observe", {**self.context(run, category, finding_id, 2), "broadcast_events": [final.model_dump(mode="json")]})
                except Exception:
                    terminal_state = "failed"
                    run.error = "Completion broadcast failed; inspect SLIM connectivity and worker logs"
                    final.claim = run.error
            await self.emit(run, final)
            # Publish the terminal state only after its last event is durable.
            # This keeps SSE readers and the next run from racing finalization.
            run.metrics.duration_seconds = round(time.monotonic() - started, 3)
            run.completed_at = now()
            run.state = terminal_state
            self.storage.save(run)

    async def intervene(self, run_id, action):
        run = self.get(run_id)
        if not run:
            raise KeyError(run_id)
        if run.state != "running" or self.gateways[run_id].gate.stopped or run_id not in self.interventions_open:
            raise ValueError("Guard changes require an active assessment before final voting")
        if run.scenario not in {"access_control", "changing_access", "tenant_invoice", "tenant_invoice_change"}:
            raise ValueError("Guard changes apply only to authorization assessments")
        if action not in {"enable_guard", "disable_guard"}:
            raise ValueError("Unknown guard action")
        patched = action == "enable_guard"
        if patched == run.patched:
            raise ValueError("Guard is already in the requested state")
        run.patched = patched
        run.environment_version += 1
        change = f"Billing probes now target the {'patched' if patched else 'vulnerable'} demo deployment." if run.scenario.startswith("tenant_invoice") else f"Authorization guard {'enabled' if patched else 'disabled'} during the assessment."
        await self.emit(run, AgentMessage(run_id=run_id, agent_id="fixture_operator", event_type=EventType.ENVIRONMENT_CHANGED, claim=f"{change} Earlier observations are retained; repeat checks against version {run.environment_version}.", data={"environment_version": run.environment_version, "action": action}))
        return run

    @staticmethod
    def mark_human(run, finding_id, reason):
        if not run.findings:
            run.findings.append(Finding(finding_id=finding_id, run_id=run.run_id, title="Assessment requires review", category="safety", route="/checks", confidence=0, initial_confidence=0,
                status=Status.NEEDS_HUMAN, remediation="Review the blocked action or missing evidence before starting another scoped assessment.", rule=reason,
                baseline={"single_agent": "NEEDS_HUMAN", "simple_majority": "NEEDS_HUMAN"}))
        for finding in run.findings:
            finding.status = Status.NEEDS_HUMAN
            finding.rule = reason

    async def stop(self, run_id):
        run = self.get(run_id)
        if not run:
            raise KeyError(run_id)
        if run.state not in {"queued", "running"}:
            return run
        self.gateways[run_id].gate.stopped = True
        task = self.tasks.get(run_id)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                # Cancellation can happen before execute() enters its try/finally.
                run.state = "stopped"
                self.mark_human(run, uid("finding"), "USER_STOP: assessment cancelled before execution")
                run.completed_at = now()
                await self.emit(run, AgentMessage(run_id=run_id, agent_id="safety_gate", event_type=EventType.ASSESSMENT_STOPPED, claim="Run cancelled before any tools executed."))
        return run


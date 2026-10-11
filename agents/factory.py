from agents.recon import ReconAgent
from agents.injection import InjectionAgent
from agents.access_control import AccessControlAgent
from agents.hardening import HardeningAgent
from agents.evidence_skeptic import EvidenceSkeptic
from agents.risk_remediation import RiskRemediationAgent
from agents.base import Specialist

CLASSES = {"recon_agent": ReconAgent, "injection_agent": InjectionAgent, "access_control_agent": AccessControlAgent,
           "hardening_agent": HardeningAgent, "evidence_skeptic": EvidenceSkeptic, "risk_remediation_agent": RiskRemediationAgent}


def create_agent(capability):
    return CLASSES.get(capability.agent_id, Specialist)(capability)


import httpx
import pytest
from app.capability_discovery import CapabilityDiscovery
from app.run_service import RunService
from app.storage import Storage
from app.transports.memory_test import MemoryTestTransport
from lab_target.app import app as fixture
from tools.lab_client import LabClient


@pytest.fixture
def service():
    store = Storage(":memory:")
    registry = CapabilityDiscovery()
    service = RunService(store, registry, LabClient("http://lab-target:8001", transport=httpx.ASGITransport(app=fixture)))
    service.transport = MemoryTestTransport(registry, lambda run_id: service.gateways[run_id], allow_model=False)
    yield service
    store.db.close()


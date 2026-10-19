import pytest
from aics_conformance.fakes import FakeServer
@pytest.fixture
def server(): return FakeServer()
@pytest.fixture
def ctx(server): return server.context()

"""Configurable in-process wire server (never imports the production server)."""
from .server import FakeServer
__all__=['FakeServer']

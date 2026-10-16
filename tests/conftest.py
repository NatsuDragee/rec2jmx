import os
import socket
from pathlib import Path

import pytest

from rec2jmx import service
from rec2jmx.analysis.grouping import GroupingSettings
from rec2jmx.loader import load_bytes, load_file
from rec2jmx.validate import find_jmeter

FIXTURES = Path(__file__).parent / "fixtures"

# Fake credentials used in fixtures; tests assert none of them leak into output.
FIXTURE_SECRETS = [
    "Sup3rS3cret!",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.ZmFrZS1zaWduYXR1cmUtZm9yLXRlc3Rz",
    "k-1234567890abcdef",
    "tok_live_ABCDEF1234567890",
    "pw-Example-42",
    "pm-token-0123456789abcdef",
    "ak-99887766554433",
    "legacyPassw0rd",
    "at-a1b2c3d4e5f60718",
]


def fixture(path: str) -> str:
    return str(FIXTURES / path)


def load(path: str, **kw):
    return load_file(fixture(path), **kw)


def build(path: str, settings: GroupingSettings | None = None):
    rec = load(path)
    analysis = service.analyze(rec, settings)
    return analysis, service.default_plan(analysis)


def from_text(text: str, filename: str = "input.txt", **kw):
    return load_bytes(text.encode("utf-8"), filename, **kw)


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    """Fail any test that tries to open a non-loopback connection."""
    real_connect = socket.socket.connect

    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise AssertionError(f"test attempted a network connection to {host!r}")
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture(scope="session")
def jmeter():
    path = find_jmeter(os.environ.get("JMETER_HOME"))
    if not path:
        pytest.skip("Apache JMeter not found (set JMETER_HOME); JMeter-based validation not performed")
    return path

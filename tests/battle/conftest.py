"""Pytest fixtures for battle test target management.

Each fixture verifies that its corresponding vulnerable application is
reachable.  If the target is not running the test is skipped, which
keeps the regular CI green while still allowing manual or scheduled
battle-test runs against live Docker containers.
"""

import pytest
import requests


def is_target_healthy(url: str, timeout: int = 5) -> bool:
    """Return True if *url* responds with a non-5xx status code."""
    try:
        resp = requests.get(url, timeout=timeout)
        return resp.status_code < 500
    except Exception:
        return False


@pytest.fixture(scope="session")
def juiceshop() -> str:
    """Ensure Juice Shop is running on localhost:3000."""
    if not is_target_healthy("http://localhost:3000"):
        pytest.skip("Juice Shop not running on localhost:3000")
    return "http://localhost:3000"


@pytest.fixture(scope="session")
def dvwa() -> str:
    """Ensure DVWA is running on localhost:4280."""
    if not is_target_healthy("http://localhost:4280"):
        pytest.skip("DVWA not running on localhost:4280")
    return "http://localhost:4280"


@pytest.fixture(scope="session")
def webgoat() -> str:
    """Ensure WebGoat is running on localhost:4281."""
    if not is_target_healthy("http://localhost:4281"):
        pytest.skip("WebGoat not running on localhost:4281")
    return "http://localhost:4281"

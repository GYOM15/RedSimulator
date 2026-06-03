"""MITM proxy module for traffic interception and analysis.

Requires mitmproxy (optional dependency):
    pip install redsimulator[proxy]
"""

from .feed import ProxyFeedAdapter
from .interceptor import MITMPROXY_AVAILABLE
from .models import CapturedFlow, ProxyConfig
from .replayer import FlowReplayer
from .server import ProxyServer
from .store import FlowStore

__all__ = [
    "MITMPROXY_AVAILABLE",
    "CapturedFlow",
    "FlowReplayer",
    "FlowStore",
    "ProxyConfig",
    "ProxyFeedAdapter",
    "ProxyServer",
]

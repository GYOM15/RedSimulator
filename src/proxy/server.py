"""MITM proxy server wrapping mitmproxy.

Runs mitmproxy in a background thread, exposing start/stop controls.
Gracefully degrades if mitmproxy is not installed.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable

from src.infra.config import settings
from src.infra.decorators import logged
from src.infra.exceptions import ProxyNotAvailableError
from src.infra.logging import get_logger

from .interceptor import MITMPROXY_AVAILABLE
from .models import CapturedFlow, ProxyConfig
from .store import FlowStore

logger = get_logger(__name__)


class ProxyServer:
    """MITM proxy server with start/stop lifecycle.

    The proxy runs mitmproxy's ``DumpMaster`` in a daemon thread so it
    does not block the main application (FastAPI event loop, CLI, etc.).

    If mitmproxy is not installed the server reports itself as unavailable
    and raises ``ProxyNotAvailableError`` on ``start()``.
    """

    def __init__(
        self,
        config: ProxyConfig | None = None,
        store: FlowStore | None = None,
        on_flow: Callable[[CapturedFlow], None] | None = None,
    ):
        if not MITMPROXY_AVAILABLE:
            logger.warning("mitmproxy not installed. Proxy features disabled.")
            logger.warning("Install with: pip install redsimulator[proxy]")

        self.config = config or ProxyConfig(
            listen_host=settings.proxy_host,
            listen_port=settings.proxy_port,
            ssl_insecure=settings.proxy_ssl_insecure,
        )
        self.store = store or FlowStore(settings.proxy_db_path)
        self.on_flow = on_flow
        self._thread: threading.Thread | None = None
        self._master = None  # mitmproxy DumpMaster
        self._running = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """Whether the proxy is currently accepting traffic."""
        return self._running

    @property
    def available(self) -> bool:
        """Whether the mitmproxy dependency is installed."""
        return MITMPROXY_AVAILABLE

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @logged
    def start(self) -> None:
        """Start the proxy in a background daemon thread.

        Raises:
            ProxyNotAvailableError: if mitmproxy is not installed.
        """
        if not MITMPROXY_AVAILABLE:
            raise ProxyNotAvailableError(
                "mitmproxy is not installed. Install with: pip install redsimulator[proxy]"
            )

        with self._lock:
            if self._running:
                logger.warning(
                    "Proxy already running on %s:%d",
                    self.config.listen_host,
                    self.config.listen_port,
                )
                return

            self._thread = threading.Thread(
                target=self._run,
                name="redsimulator-proxy",
                daemon=True,
            )
            self._thread.start()
            self._running = True

        logger.info(
            "Proxy started on %s:%d",
            self.config.listen_host,
            self.config.listen_port,
        )

    @logged
    def stop(self) -> None:
        """Stop the proxy gracefully."""
        with self._lock:
            if not self._running:
                return
            if self._master:
                self._master.shutdown()
            self._running = False

        logger.info("Proxy stopped")

    def clear_flows(self) -> int:
        """Delete all captured flows from the store.

        Returns:
            Number of flows deleted.
        """
        return self.store.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """Run mitmproxy's DumpMaster in the current (daemon) thread.

        This method creates its own asyncio event loop because mitmproxy
        requires one and the daemon thread does not have one by default.
        """
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        from .interceptor import RequestInterceptor

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        opts = options.Options(
            listen_host=self.config.listen_host,
            listen_port=self.config.listen_port,
            ssl_insecure=self.config.ssl_insecure,
        )

        self._master = DumpMaster(opts)
        interceptor = RequestInterceptor(
            store=self.store,
            config=self.config,
            on_flow=self.on_flow,
        )
        self._master.addons.add(interceptor)

        try:
            self._master.run()
        except Exception:
            logger.exception("Proxy server error")
        finally:
            self._running = False
            loop.close()

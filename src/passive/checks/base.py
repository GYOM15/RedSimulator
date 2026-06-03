"""Abstract base class for passive checks.

Each passive check analyzes an HTTP response (headers, body, cookies)
and returns a list of findings without sending any new requests.
"""

from abc import ABC, abstractmethod

from src.passive.models import PassiveFinding


class PassiveCheck(ABC):
    """Base class for all passive security checks.

    Subclasses must define ``name`` and ``description`` class attributes,
    and implement the ``check`` method.
    """

    name: str
    description: str

    @abstractmethod
    def check(
        self,
        url: str,
        status_code: int,
        headers: dict,
        body: str,
        cookies: list[dict] | None = None,
    ) -> list[PassiveFinding]:
        """Analyze a response and return findings.

        Args:
            url: The URL that was requested.
            status_code: HTTP status code of the response.
            headers: Response headers as a dict (keys are case-insensitive).
            body: Response body as text.
            cookies: Parsed cookie dicts with keys: name, value, flags.

        Returns:
            List of findings detected in this response.
        """

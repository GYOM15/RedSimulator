"""Secure string handling for sensitive values like API keys.

The SecureString class wraps a string value and ensures it is NEVER
exposed through repr(), str(), logging, serialization, or any other
side channel. The actual value is only accessible through the
explicit .get_secret_value() method.
"""

from __future__ import annotations


class SecureString:
    """A string that is never accidentally exposed."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        """Explicitly retrieve the secret value."""
        return self._value

    def __repr__(self) -> str:
        return "SecureString('****')"

    def __str__(self) -> str:
        return "****"

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecureString):
            return self._value == other._value
        return False

    def __hash__(self) -> int:
        return hash(self._value)

    # Prevent pickle/json serialization
    def __getstate__(self):
        raise TypeError("SecureString cannot be serialized")

    def __reduce__(self):
        raise TypeError("SecureString cannot be pickled")

"""Exceptions of the TMSG (Tencoin Message) package."""

from typing import Optional


class TMSGError(Exception):
    """Base class for every TMSG error."""


class TMSGKeyError(TMSGError, ValueError):
    """A public or private key is malformed, not on the curve, or cannot be resolved."""


class TMSGFormatError(TMSGError, ValueError):
    """The data is not a valid TMSG payload (bad magic, version, length, hex, archive...)."""


class TMSGDecryptionError(TMSGError, ValueError):
    """Authentication failed: wrong key, or the payload was modified."""


class TMSGSizeError(TMSGError, ValueError):
    """
    The message does not fit (OP_RETURN limit, file limit) or has a size that nodes
    cannot parse safely.

    Attributes:
        size:           payload size in bytes that was attempted
        limit:          maximum allowed payload size (None if not a limit problem)
        pad_bytes:      for unsafe OP_RETURN sizes: how many bytes must be added to the
                        plaintext to reach a safe size (None otherwise)
    """

    def __init__(self, message: str, *, size: Optional[int] = None,
                 limit: Optional[int] = None, pad_bytes: Optional[int] = None):
        super().__init__(message)
        self.size = size
        self.limit = limit
        self.pad_bytes = pad_bytes


class TMSGDependencyError(TMSGError, ImportError):
    """A required third-party package (coincurve, cryptography) is not installed."""

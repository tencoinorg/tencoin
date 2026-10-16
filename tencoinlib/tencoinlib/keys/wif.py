"""
WIF (Wallet Import Format): hex <-> WIF conversion of private keys.

    WIF = Base58Check( version || 32-byte private key [|| 0x01] )

The trailing 0x01 marks a **compressed** key: the public key (and so the address) of such a
key is the 33-byte compressed point. A WIF without it describes the **uncompressed** 65-byte
public key. The same private key gives different public keys (and different P2PKH addresses)
in the two forms, so the flag must be kept when moving a key between wallets.

    hex_to_wif("c0e1...")                    -> compressed WIF
    hex_to_wif("c0e1...", compressed=False)  -> uncompressed WIF
    wif_to_hex(wif)                          -> hex of the private key
    decode_wif(wif)                          -> WIFKey(private_key, compressed, version, .public_key, ...)

The version byte defaults to ``constants.WIF_VERSION`` (an assumption, see there); pass
``version=`` to use another one, or ``version=None`` when decoding to accept any.

NEVER log or print a WIF or a private key.
"""

import re
from dataclasses import dataclass
from typing import Dict, Optional, Union

from ..constants import WIF_VERSION
from ..utils import base58check_decode, base58check_encode
from . import pubkey as _pk
from .ec import N as CURVE_ORDER

__all__ = [
    "WIFError", "WIFKey", "WIF_VERSION", "PrivateKeyInfo",
    "encode_wif", "decode_wif", "hex_to_wif", "wif_to_hex",
    "parse_private_key", "to_private_key_bytes",
]

_HEX_KEY = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")


class WIFError(ValueError):
    """Invalid WIF or private key."""


def _coerce_private_key(value: Union[bytes, bytearray, str]) -> bytes:
    """32 bytes or 64 hex chars (0x prefix / surrounding whitespace allowed) -> checked bytes."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) != 32:
            raise WIFError(f"private key must be 32 bytes, got {len(raw)}")
    elif isinstance(value, str):
        text = "".join(value.split())
        if not _HEX_KEY.match(text):
            raise WIFError("private key must be 64 hex characters (32 bytes)")
        raw = bytes.fromhex(text[2:] if text[:2].lower() == "0x" else text)
    else:
        raise WIFError(f"private key must be bytes or hex str, got {type(value).__name__}")
    if not 0 < int.from_bytes(raw, "big") < CURVE_ORDER:
        raise WIFError("private key is out of range (must be between 1 and the curve order - 1)")
    return raw


def _check_version(version: Optional[int]) -> None:
    if version is not None and (isinstance(version, bool) or not isinstance(version, int)
                                or not 0 <= version <= 0xFF):
        raise WIFError(f"version must be a byte (0..255), got {version!r}")


@dataclass(frozen=True)
class WIFKey:
    """A decoded WIF: the private key, its compression flag, and the version byte."""

    private_key: bytes
    compressed: bool
    version: int = WIF_VERSION

    def __repr__(self) -> str:        # never show the key
        return f"WIFKey(compressed={self.compressed}, version=0x{self.version:02x}, private_key=<hidden>)"

    @property
    def hex(self) -> str:
        """The private key as 64 hex characters."""
        return self.private_key.hex()

    @property
    def public_key(self) -> bytes:
        """Public key in the form this WIF stands for: 33 bytes if compressed, else 65."""
        return _pk.private_key_to_public_key(self.private_key, self.compressed)

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    @property
    def wif(self) -> str:
        return encode_wif(self.private_key, self.compressed, self.version)

    def address(self, kind: str = "p2pkh") -> str:
        """
        Address of this key in its own form ("p2pkh", "p2wpkh" or "p2sh-p2wpkh");
        SegWit kinds are only possible for compressed keys.
        """
        return _pk.public_key_to_address(self.public_key, kind)

    def addresses(self) -> Dict[str, str]:
        """Every address this key can have: P2PKH always, the SegWit kinds if compressed."""
        kinds = ("p2pkh", "p2wpkh", "p2sh-p2wpkh") if self.compressed else ("p2pkh",)
        return {kind: self.address(kind) for kind in kinds}


def encode_wif(
    private_key: Union[bytes, bytearray, str],
    compressed: bool = True,
    version: int = WIF_VERSION,
) -> str:
    """
    Private key (32 bytes or hex) -> WIF.

    Args:
        compressed: True (default) appends the 0x01 flag: the key's public key is the
                    compressed one. False gives the legacy uncompressed form.
        version:    WIF version byte (default ``constants.WIF_VERSION``).

    Raises:
        WIFError
    """
    _check_version(version)
    if version is None:
        raise WIFError("version is required to encode a WIF")
    raw = _coerce_private_key(private_key)
    payload = raw + b"\x01" if compressed else raw
    return base58check_encode(version, payload)


def decode_wif(wif: str, version: Optional[int] = WIF_VERSION) -> WIFKey:
    """
    WIF -> WIFKey (``.private_key``, ``.hex``, ``.compressed``, ``.public_key``, ``.address()``).

    Args:
        version: expected version byte (default ``constants.WIF_VERSION``); a different one
                 is an error, so a key of another network is not imported by accident.
                 ``None`` accepts any version (it is reported in ``.version``).

    Raises:
        WIFError: bad characters / checksum, wrong length or compression flag, wrong version,
                  or a private key outside 1..curve order - 1.
    """
    _check_version(version)
    if not isinstance(wif, str):
        raise WIFError(f"WIF must be a string, got {type(wif).__name__}")
    text = wif.strip()
    if not text:
        raise WIFError("WIF is empty")
    try:
        found_version, payload = base58check_decode(text)
    except ValueError:
        raise WIFError("invalid WIF: bad characters or checksum mismatch") from None

    if version is not None and found_version != version:
        raise WIFError(
            f"WIF version byte is 0x{found_version:02x}, expected 0x{version:02x} "
            "(pass version=None to accept any version)"
        )
    if len(payload) == 32:
        compressed = False
    elif len(payload) == 33:
        if payload[-1] != 0x01:
            raise WIFError("invalid WIF: the compression flag must be 0x01")
        compressed, payload = True, payload[:-1]
    else:
        raise WIFError(f"invalid WIF: payload is {len(payload)} bytes, expected 32 or 33")
    return WIFKey(_coerce_private_key(payload), compressed, found_version)


@dataclass(frozen=True)
class PrivateKeyInfo:
    """A private key of unknown format, after detection (see ``parse_private_key``)."""

    private_key: bytes
    format: str                     # "bytes" | "hex" | "wif"
    compressed: Optional[bool]      # known for a WIF; None for bytes / hex (the flag is not in them)
    version: Optional[int] = None   # WIF version byte (WIF only)

    def __repr__(self) -> str:      # never show the key
        return f"PrivateKeyInfo(format={self.format!r}, compressed={self.compressed}, private_key=<hidden>)"


def parse_private_key(
    value: Union[bytes, bytearray, str],
    version: Optional[int] = WIF_VERSION,
) -> PrivateKeyInfo:
    """
    Accept a private key in ANY supported form and detect which one it is:

      * 32 bytes
      * 64 hex characters (``0x`` prefix and whitespace allowed)
      * a WIF string (compressed or uncompressed: the flag is read from the WIF)

    ``version`` is the expected WIF version byte (``None`` = accept any).

    Raises:
        WIFError: not a 32-byte key, not 64 hex characters and not a valid WIF.
    """
    if isinstance(value, (bytes, bytearray)):
        return PrivateKeyInfo(_coerce_private_key(value), "bytes", None)
    if not isinstance(value, str):
        raise WIFError(f"private key must be bytes, hex or WIF, got {type(value).__name__}")
    text = "".join(value.split())
    if _HEX_KEY.match(text):
        return PrivateKeyInfo(_coerce_private_key(text), "hex", None)
    try:
        key = decode_wif(text, version)
    except WIFError as exc:
        raise WIFError(f"not a private key in hex (64 characters) or WIF form: {exc}") from None
    return PrivateKeyInfo(key.private_key, "wif", key.compressed, key.version)


def to_private_key_bytes(
    value: Union[bytes, bytearray, str],
    version: Optional[int] = WIF_VERSION,
) -> bytes:
    """32-byte private key from bytes, hex or WIF (see ``parse_private_key``)."""
    return parse_private_key(value, version).private_key


def hex_to_wif(
    hex_key: Union[str, bytes, bytearray],
    compressed: bool = True,
    version: int = WIF_VERSION,
) -> str:
    """Private key hex (64 chars, ``0x`` allowed) -> WIF. ``compressed=False`` for the legacy form."""
    return encode_wif(hex_key, compressed, version)


def wif_to_hex(wif: str, version: Optional[int] = WIF_VERSION) -> str:
    """
    WIF -> private key hex (64 chars). The compression flag is not part of the hex: use
    ``decode_wif()`` when you also need it.
    """
    return decode_wif(wif, version).hex

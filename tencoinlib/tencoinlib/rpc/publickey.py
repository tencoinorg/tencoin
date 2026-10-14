"""
getpublickey support: result type and local verification.

The node command ``getpublickey`` searches the chain for the public key of an address.
An address is only a HASH160 of the key, so the key is on-chain only after the address
has spent an output (it then appears in the scriptSig or witness of that input).

The node's answer is never trusted blindly: ``parse_get_public_key_response`` checks
that the returned key really hashes to the requested address.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..constants import SECP256K1_FIELD_PRIME as _P
from ..transaction.address import AddressError, decode_address
from ..utils import hash160
from .exceptions import PublicKeyNotFoundError, PublicKeyVerificationError, ResponseError


def _on_curve(x: int, y: int) -> bool:
    return 0 < x < _P and 0 < y < _P and (y * y - x * x * x - 7) % _P == 0


def compress_public_key(pubkey: bytes) -> bytes:
    """
    Return the 33-byte compressed form of a compressed or uncompressed public key.

    Raises:
        ValueError: wrong length / prefix, or the point is not on secp256k1.
    """
    pubkey = bytes(pubkey)
    if len(pubkey) == 33 and pubkey[0] in (2, 3):
        x = int.from_bytes(pubkey[1:], "big")
        if not 0 < x < _P:
            raise ValueError("public key x-coordinate out of range")
        y_sq = (pow(x, 3, _P) + 7) % _P
        y = pow(y_sq, (_P + 1) // 4, _P)
        if (y * y) % _P != y_sq:
            raise ValueError("public key is not a point on secp256k1")
        return pubkey
    if len(pubkey) == 65 and pubkey[0] == 4:
        x = int.from_bytes(pubkey[1:33], "big")
        y = int.from_bytes(pubkey[33:], "big")
        if not _on_curve(x, y):
            raise ValueError("public key is not a point on secp256k1")
        return bytes([2 + (y & 1)]) + pubkey[1:33]
    raise ValueError(
        f"public key must be 33 bytes (02/03...) or 65 bytes (04...), got {len(pubkey)} bytes"
    )


def public_key_matches_address(pubkey: bytes, address: str) -> bool:
    """
    True if ``pubkey`` is the key behind ``address``.

    Supports P2PKH (compressed or uncompressed key), P2WPKH and P2SH-P2WPKH
    (nested SegWit). P2WSH / script-hash multisig addresses have no single key: False.
    """
    try:
        addr_type, addr_hash = decode_address(address)
    except AddressError:
        return False
    pubkey = bytes(pubkey)
    if addr_type == "p2pkh":
        return hash160(pubkey) == addr_hash
    if addr_type == "p2wpkh":
        return len(pubkey) == 33 and hash160(pubkey) == addr_hash
    if addr_type == "p2sh":
        return len(pubkey) == 33 and hash160(b"\x00\x14" + hash160(pubkey)) == addr_hash
    return False


@dataclass(frozen=True)
class PublicKeyInfo:
    """Public key of an address, as found on-chain by ``getpublickey``."""

    address: str
    public_key: bytes                 # exactly as revealed on-chain (33 or 65 bytes)
    format: str                       # "compressed" | "uncompressed"
    txid: Optional[str] = None        # transaction that revealed the key
    input_index: Optional[int] = None
    location: Optional[str] = None    # "witness" | "scriptSig"
    height: Optional[int] = None
    node_verified: bool = False       # the node's own "verified" flag

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    @property
    def compressed(self) -> bytes:
        """33-byte compressed form (what TMSG encryption uses)."""
        return compress_public_key(self.public_key)

    def __repr__(self) -> str:
        return (f"PublicKeyInfo(address={self.address!r}, "
                f"public_key={self.public_key_hex[:12]}..., format={self.format!r}, "
                f"txid={self.txid!r}, height={self.height!r})")


def parse_get_public_key_response(address: str, result: Dict[str, Any]) -> PublicKeyInfo:
    """
    Turn a ``getpublickey`` response into a verified PublicKeyInfo.

    Raises:
        PublicKeyNotFoundError:      the address never revealed its key
        PublicKeyVerificationError:  malformed answer, or the key does not belong to the address
        ResponseError:               other node-side failure
    """
    if not isinstance(result, dict):
        raise ResponseError("getpublickey: unexpected response")

    if result.get("success") is False or "public_key" not in result:
        error = str(result.get("error", "")) or "getpublickey failed"
        if "no public key" in error.lower():
            raise PublicKeyNotFoundError(address, error)
        raise ResponseError(f"getpublickey: {error}")

    returned_address = result.get("address")
    if returned_address is not None and returned_address != address:
        raise PublicKeyVerificationError(
            f"node answered for a different address ({returned_address!r}, asked {address!r})"
        )

    try:
        pubkey = bytes.fromhex(str(result["public_key"]).strip())
        compress_public_key(pubkey)       # shape + on-curve check
    except (ValueError, TypeError) as exc:
        raise PublicKeyVerificationError(f"node returned an invalid public key: {exc}") from exc

    fmt = "compressed" if len(pubkey) == 33 else "uncompressed"
    if result.get("format") not in (None, fmt):
        raise PublicKeyVerificationError(
            f"node says format {result.get('format')!r} but the key is {fmt}"
        )

    if not public_key_matches_address(pubkey, address):
        raise PublicKeyVerificationError(
            "the public key returned by the node does not hash to the address; refusing to use it"
        )

    source = result.get("source") or {}
    return PublicKeyInfo(
        address=address,
        public_key=pubkey,
        format=fmt,
        txid=source.get("txid"),
        input_index=source.get("input_index"),
        location=source.get("location"),
        height=source.get("height"),
        node_verified=bool(result.get("verified", False)),
    )

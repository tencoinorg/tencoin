"""
Public-key formats: compressed (33 bytes, 02/03 + x) and uncompressed (65 bytes, 04 + x + y).

Both are accepted everywhere a public key is read. P2PKH addresses can commit to either
form (the hash of the exact bytes), while SegWit addresses (P2WPKH, P2SH-P2WPKH) only
allow compressed keys.
"""

from typing import Optional

from ..constants import P2PKH_VERSION, SECP256K1_FIELD_PRIME as _P
from ..utils import base58check_encode, hash160

__all__ = [
    "is_compressed", "compress_public_key", "decompress_public_key", "convert_public_key",
    "private_key_to_public_key", "public_key_to_address", "public_key_for_hash160",
]


def _lift_x(x: int, odd: bool) -> int:
    """y for a given x and parity, or ValueError if x is not on the curve."""
    if not 0 < x < _P:
        raise ValueError("public key x-coordinate out of range")
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if (y * y) % _P != y_sq:
        raise ValueError("public key is not a point on secp256k1")
    return _P - y if (y & 1) != int(odd) else y


def _parse(pubkey: bytes):
    """Validate a public key and return (x, y, compressed). Raises ValueError."""
    pubkey = bytes(pubkey)
    if len(pubkey) == 33 and pubkey[0] in (2, 3):
        x = int.from_bytes(pubkey[1:], "big")
        return x, _lift_x(x, pubkey[0] == 3), True
    if len(pubkey) == 65 and pubkey[0] == 4:
        x = int.from_bytes(pubkey[1:33], "big")
        y = int.from_bytes(pubkey[33:], "big")
        if not (0 < x < _P and 0 < y < _P and (y * y - x * x * x - 7) % _P == 0):
            raise ValueError("public key is not a point on secp256k1")
        return x, y, False
    raise ValueError(
        f"public key must be 33 bytes (02/03...) or 65 bytes (04...), got {len(pubkey)} bytes"
    )


def is_compressed(pubkey: bytes) -> bool:
    """True for a valid 33-byte key, False for a valid 65-byte key. ValueError otherwise."""
    return _parse(pubkey)[2]


def compress_public_key(pubkey: bytes) -> bytes:
    """
    33-byte compressed form of a compressed or uncompressed public key.

    Raises:
        ValueError: wrong length / prefix, or the point is not on secp256k1.
    """
    x, y, _ = _parse(pubkey)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def decompress_public_key(pubkey: bytes) -> bytes:
    """
    65-byte uncompressed form (04 + x + y) of a compressed or uncompressed public key.

    Raises:
        ValueError: wrong length / prefix, or the point is not on secp256k1.
    """
    x, y, _ = _parse(pubkey)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def convert_public_key(pubkey: bytes, compressed: bool) -> bytes:
    """Return ``pubkey`` in the requested form (compressed=True -> 33 bytes, False -> 65)."""
    return compress_public_key(pubkey) if compressed else decompress_public_key(pubkey)


def private_key_to_public_key(private_key: bytes, compressed: bool = True) -> bytes:
    """Public key of a 32-byte private key, compressed (33 bytes) or uncompressed (65 bytes)."""
    from .ec import privkey_to_pubkey

    private_key = bytes(private_key)
    if len(private_key) != 32:
        raise ValueError(f"private key must be 32 bytes, got {len(private_key)}")
    return privkey_to_pubkey(private_key, compressed=compressed)


def public_key_to_address(pubkey: bytes, kind: str = "p2pkh") -> str:
    """
    Address of a public key.

    kind="p2pkh"        T...   works for compressed AND uncompressed keys (a different
                               address for each form of the same key)
    kind="p2wpkh"       tc1q...   compressed keys only
    kind="p2sh-p2wpkh"  M...   compressed keys only

    Raises:
        ValueError: invalid key, unknown kind, or an uncompressed key for a SegWit kind.
    """
    compressed = is_compressed(pubkey)
    pubkey = bytes(pubkey)
    kind = kind.lower().strip()
    if kind == "p2pkh":
        return base58check_encode(P2PKH_VERSION, hash160(pubkey))
    if kind in ("p2wpkh", "p2sh-p2wpkh"):
        if not compressed:
            raise ValueError(f"{kind} addresses need a compressed public key")
        if kind == "p2wpkh":
            from .bip84 import public_key_to_segwit_v0
            return public_key_to_segwit_v0(pubkey)
        from .bip49 import public_key_to_p2sh_segwit
        return public_key_to_p2sh_segwit(pubkey)
    raise ValueError("kind must be 'p2pkh', 'p2wpkh' or 'p2sh-p2wpkh'")


def public_key_for_hash160(
    private_key: bytes, target_hash: bytes, *, allow_uncompressed: bool = True
) -> Optional[bytes]:
    """
    The public key of ``private_key`` whose HASH160 equals ``target_hash``: the compressed
    form first, then (if allowed) the uncompressed form. None if neither matches.
    """
    compressed = private_key_to_public_key(private_key, compressed=True)
    if hash160(compressed) == target_hash:
        return compressed
    if allow_uncompressed:
        uncompressed = private_key_to_public_key(private_key, compressed=False)
        if hash160(uncompressed) == target_hash:
            return uncompressed
    return None

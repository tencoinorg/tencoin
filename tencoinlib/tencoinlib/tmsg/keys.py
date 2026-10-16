"""
Key handling for TMSG: parsing, validation and normalisation of public / private keys.

Public keys may be given as
  * bytes   - 33 (compressed) or 65 (uncompressed) bytes
  * str     - hex of such a key ("0x" prefix allowed), or several keys separated by
              whitespace / commas / semicolons
  * address - any Tencoin address; its key is looked up on-chain with ``rpc.get_public_key``
              (requires ``rpc=``; the lookup only works for addresses that have spent before)
  * PublicKeyInfo - the result of ``rpc.get_public_key``
"""

import re
from typing import Any, Iterable, List, Optional, Union

from ..constants import TMSG_MAX_RECIPIENTS
from ..rpc.publickey import PublicKeyInfo, compress_public_key
from .errors import TMSGDependencyError, TMSGKeyError

PublicKeyLike = Union[bytes, bytearray, str, PublicKeyInfo]
PrivateKeyLike = Union[bytes, bytearray, str]

_HEX_PUBKEY = re.compile(r"^(?:0x)?(?:[0-9a-fA-F]{66}|[0-9a-fA-F]{130})$")
_SEPARATORS = re.compile(r"[\s,;]+")


def load_coincurve():
    """Import coincurve lazily, with a readable error."""
    try:
        import coincurve
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise TMSGDependencyError(
            "TMSG needs the 'coincurve' package: pip install coincurve"
        ) from exc
    return coincurve


def normalize_public_key(key: PublicKeyLike, *, rpc: Any = None) -> bytes:
    """
    Return the 33-byte compressed form of a public key.

    Raises:
        TMSGKeyError: wrong type / length / prefix, point not on secp256k1, or an address
                      was given without ``rpc``.
        PublicKeyNotFoundError: (address given) the address never revealed its key.
    """
    if isinstance(key, PublicKeyInfo):
        return key.compressed

    if isinstance(key, (bytes, bytearray)):
        raw = bytes(key)
    elif isinstance(key, str):
        text = key.strip()
        if _HEX_PUBKEY.match(text):
            raw = bytes.fromhex(text[2:] if text[:2].lower() == "0x" else text)
        else:
            if rpc is None:
                raise TMSGKeyError(
                    f"{text[:20]!r} is not a hex public key. To encrypt to an address, "
                    "pass rpc= so its public key can be looked up on-chain."
                )
            return rpc.get_public_key(text).compressed      # verified by the client
    else:
        raise TMSGKeyError(f"public key must be bytes, hex str, address or PublicKeyInfo, "
                           f"got {type(key).__name__}")

    try:
        return compress_public_key(raw)
    except ValueError as exc:
        raise TMSGKeyError(f"invalid public key: {exc}") from exc


def parse_public_keys(
    recipients: Union[PublicKeyLike, Iterable[PublicKeyLike]],
    *,
    rpc: Any = None,
    dedupe: bool = True,
) -> List[bytes]:
    """
    Normalise one or many recipients into a list of compressed public keys.

    Duplicates (after normalisation) are dropped, keeping the first occurrence.

    Raises:
        TMSGKeyError: nothing usable, an invalid key, or more than 255 recipients.
    """
    if isinstance(recipients, (bytes, bytearray, PublicKeyInfo)):
        items: List[Any] = [recipients]
    elif isinstance(recipients, str):
        items = [t for t in _SEPARATORS.split(recipients.strip()) if t]
    else:
        items = []
        try:
            for item in recipients:
                if isinstance(item, str):
                    items.extend(t for t in _SEPARATORS.split(item.strip()) if t)
                else:
                    items.append(item)
        except TypeError:
            raise TMSGKeyError("recipients must be a key or an iterable of keys") from None

    if not items:
        raise TMSGKeyError("at least one recipient public key is required")

    keys: List[bytes] = []
    seen = set()
    for i, item in enumerate(items, 1):
        try:
            key = normalize_public_key(item, rpc=rpc)
        except TMSGKeyError as exc:
            raise TMSGKeyError(f"recipient #{i}: {exc}") from exc
        if dedupe and key in seen:
            continue
        seen.add(key)
        keys.append(key)

    if len(keys) > TMSG_MAX_RECIPIENTS:
        raise TMSGKeyError(f"too many recipients: {len(keys)} (max {TMSG_MAX_RECIPIENTS})")
    return keys


def normalize_private_key(key: PrivateKeyLike) -> bytes:
    """
    Return a validated 32-byte private key.

    Accepts 32 bytes, 64 hex characters, or a WIF string (compressed or uncompressed: the
    form is detected automatically; the compression flag is irrelevant for decrypting).
    """
    from ..keys.wif import WIFError, to_private_key_bytes

    try:
        raw = to_private_key_bytes(key)
    except WIFError as exc:
        raise TMSGKeyError(f"invalid private key: {exc}") from exc
    try:
        load_coincurve().PrivateKey(raw)            # rejects 0 and values >= curve order
    except TMSGDependencyError:
        raise
    except Exception as exc:
        raise TMSGKeyError(f"invalid private key: {exc}") from exc
    return raw


def normalize_private_keys(
    keys: Union[PrivateKeyLike, Iterable[PrivateKeyLike]]
) -> List[bytes]:
    """One private key or an iterable of them -> list of validated 32-byte keys."""
    if isinstance(keys, (bytes, bytearray, str)):
        keys = [keys]
    try:
        result = [normalize_private_key(k) for k in keys]
    except TypeError:
        raise TMSGKeyError("private_keys must be a key or an iterable of keys") from None
    if not result:
        raise TMSGKeyError("at least one private key is required")
    return result


def public_key_from_private_key(private_key: PrivateKeyLike) -> bytes:
    """Compressed public key (33 bytes) of a private key."""
    raw = normalize_private_key(private_key)
    return load_coincurve().PrivateKey(raw).public_key.format(compressed=True)

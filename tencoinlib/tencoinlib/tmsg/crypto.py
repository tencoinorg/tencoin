"""
TMSG core: encryption and decryption of raw bytes.

ECDH (secp256k1) + AES-256-GCM, byte-for-byte compatible with the reference
encryptor / decryptor tools.

Version 0x01 (exactly one recipient public key)::

    [4 B] "TMSG"  [1 B] 0x01  [33 B] ephemeral pubkey  [12 B] nonce  [N B] ciphertext + 16 B tag

Version 0x02 (2..255 recipients, any ONE matching private key decrypts)::

    [4 B] "TMSG"  [1 B] 0x02  [1 B] N
    N x { [33 B] ephemeral pubkey  [12 B] wrap nonce  [48 B] wrapped content key (32 B + 16 B tag) }
    [12 B] message nonce  [N B] ciphertext + 16 B tag

Key derivation: ``AES key = SHA-256(compressed(ephemeral_priv * recipient_pub))``.
v2 encrypts the data once with a random content key and wraps that key for every
recipient with a fresh ephemeral key.

TMSG authenticates the ciphertext, not the sender: anyone who knows your public key can
encrypt to you. Sign the plaintext (see tencoinlib.message) if the sender must be provable.
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Union

from ..constants import (
    OP_RETURN_MAX_DATA,
    TMSG_GCM_TAG_SIZE,
    TMSG_MAGIC,
    TMSG_MAX_RECIPIENTS,
    TMSG_NONCE_SIZE,
    TMSG_RECIPIENT_BLOCK_SIZE,
    TMSG_VERSION_1,
    TMSG_VERSION_2,
)
from .errors import TMSGDecryptionError, TMSGFormatError, TMSGSizeError
from .keys import (
    PrivateKeyLike,
    PublicKeyLike,
    load_coincurve,
    normalize_private_keys,
    parse_public_keys,
)

# AES-GCM in `cryptography` accepts at most 2**31 - 1 bytes in one call.
MAX_PLAINTEXT_SIZE = 2**31 - 1 - TMSG_GCM_TAG_SIZE
# Hex payloads typed / pasted by a user are capped like the reference tool does.
MAX_HEX_PAYLOAD_BYTES = 10 * 1024 * 1024

_V1_FIXED = 4 + 1 + 33 + TMSG_NONCE_SIZE          # magic + version + eph pub + nonce
_V1_MIN = _V1_FIXED + TMSG_GCM_TAG_SIZE


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover
        from .errors import TMSGDependencyError
        raise TMSGDependencyError(
            "TMSG needs the 'cryptography' package: pip install cryptography"
        ) from exc
    return AESGCM


# ---------------------------------------------------------------------------
# Sizes
# ---------------------------------------------------------------------------

def select_version(recipients: int) -> int:
    """0x01 for exactly one recipient, 0x02 for two or more."""
    if recipients < 1:
        raise TMSGFormatError("at least one recipient is required")
    return TMSG_VERSION_1 if recipients == 1 else TMSG_VERSION_2


def overhead(recipients: int = 1, version: Optional[int] = None) -> int:
    """
    Bytes a TMSG payload adds to the plaintext.

    v1: 66 bytes.  v2: 34 + 93 per recipient.
    """
    version = select_version(recipients) if version is None else version
    if version == TMSG_VERSION_1:
        return _V1_MIN
    if version == TMSG_VERSION_2:
        return 6 + recipients * TMSG_RECIPIENT_BLOCK_SIZE + TMSG_NONCE_SIZE + TMSG_GCM_TAG_SIZE
    raise TMSGFormatError(f"unsupported version: {version:#04x}")


def max_plaintext(
    recipients: int = 1,
    version: Optional[int] = None,
    limit: int = OP_RETURN_MAX_DATA,
) -> int:
    """
    Largest plaintext (bytes) whose payload still fits in ``limit`` bytes.

    The default limit is the OP_RETURN size of the node: 958 bytes for one recipient.
    """
    return max(0, limit - overhead(recipients, version))


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TMSGInfo:
    version: int
    recipients: int             # recipient blocks (1 for v1)
    payload_size: int
    overhead: int
    plaintext_size: int


@dataclass(frozen=True)
class _Parsed:
    version: int
    blocks: tuple               # v1: ((eph, None, None),) ; v2: ((eph, wrap_nonce, wrapped_key), ...)
    nonce: bytes                # v1: nonce; v2: message nonce
    ciphertext: bytes


def _to_bytes(payload: Union[bytes, bytearray, memoryview, str]) -> bytes:
    if isinstance(payload, str):
        text = "".join(payload.split())
        if text[:2].lower() == "0x":
            text = text[2:]
        if len(text) > MAX_HEX_PAYLOAD_BYTES * 2:
            raise TMSGSizeError("hex input is too large", size=len(text) // 2,
                                limit=MAX_HEX_PAYLOAD_BYTES)
        try:
            return bytes.fromhex(text)
        except ValueError:
            raise TMSGFormatError("payload is not a valid hex string") from None
    if isinstance(payload, (bytes, bytearray, memoryview)):
        return bytes(payload)
    raise TMSGFormatError(f"payload must be bytes or hex str, got {type(payload).__name__}")


def _parse(payload: bytes) -> _Parsed:
    if len(payload) < 5:
        raise TMSGFormatError("payload too short to be a TMSG")
    if payload[:4] != TMSG_MAGIC:
        raise TMSGFormatError(f"invalid magic: expected 'TMSG', got {payload[:4]!r}")
    version = payload[4]

    if version == TMSG_VERSION_1:
        if len(payload) < _V1_MIN:
            raise TMSGFormatError("payload too short to be a TMSG v1")
        return _Parsed(
            version, ((payload[5:38], None, None),),
            payload[38:50], payload[50:],
        )

    if version == TMSG_VERSION_2:
        if len(payload) < 6:
            raise TMSGFormatError("payload too short to be a TMSG v2")
        n = payload[5]
        if n == 0:
            raise TMSGFormatError("invalid payload: recipient count is 0")
        blocks_end = 6 + n * TMSG_RECIPIENT_BLOCK_SIZE
        if len(payload) < blocks_end + TMSG_NONCE_SIZE + TMSG_GCM_TAG_SIZE:
            raise TMSGFormatError("payload too short to be a TMSG v2")
        blocks = []
        for i in range(n):
            off = 6 + i * TMSG_RECIPIENT_BLOCK_SIZE
            blocks.append((payload[off:off + 33], payload[off + 33:off + 45],
                           payload[off + 45:off + 93]))
        return _Parsed(
            version, tuple(blocks),
            payload[blocks_end:blocks_end + TMSG_NONCE_SIZE],
            payload[blocks_end + TMSG_NONCE_SIZE:],
        )

    raise TMSGFormatError(f"unsupported TMSG version: {version:#04x}")


def is_tmsg(data: Union[bytes, bytearray, memoryview, str]) -> bool:
    """Cheap check: does ``data`` look like a TMSG (magic + known version)?"""
    try:
        raw = _to_bytes(data)
    except (TMSGFormatError, TMSGSizeError):
        return False
    return len(raw) >= 5 and raw[:4] == TMSG_MAGIC and raw[4] in (TMSG_VERSION_1, TMSG_VERSION_2)


def inspect(payload: Union[bytes, bytearray, memoryview, str]) -> TMSGInfo:
    """
    Validate the structure of a payload (bytes or hex) and describe it, without a key.

    Raises:
        TMSGFormatError
    """
    raw = _to_bytes(payload)
    parsed = _parse(raw)
    return TMSGInfo(
        version=parsed.version,
        recipients=len(parsed.blocks),
        payload_size=len(raw),
        overhead=overhead(len(parsed.blocks), parsed.version),
        plaintext_size=len(parsed.ciphertext) - TMSG_GCM_TAG_SIZE,
    )


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def _shared_secret(private_key, public_key) -> bytes:
    shared_point = public_key.multiply(private_key.secret)
    return hashlib.sha256(shared_point.format(compressed=True)).digest()


def _wrap_for(cc, recipient_pub: bytes):
    """(ephemeral pubkey, AES key) for one recipient."""
    eph = cc.PrivateKey()
    shared = _shared_secret(eph, cc.PublicKey(recipient_pub))
    return eph.public_key.format(compressed=True), shared


def encrypt(
    data: Union[bytes, bytearray, memoryview],
    recipients: Union[PublicKeyLike, Iterable[PublicKeyLike]],
    *,
    version: Optional[int] = None,
    rpc: Any = None,
) -> bytes:
    """
    Encrypt raw bytes to one or more public keys and return a TMSG payload.

    Args:
        data:       the plaintext.
        recipients: a public key or a list of them (see tmsg.keys). Duplicates are dropped.
        version:    None = automatic (1 key -> v1, 2+ keys -> v2, recommended).
                    Forcing 1 needs exactly one key; forcing 2 with one key is valid
                    but wastes 93 bytes.
        rpc:        needed only when a recipient is an address.

    Raises:
        TMSGKeyError, TMSGFormatError, TMSGSizeError
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes-like, got {type(data).__name__}")
    data = bytes(data)
    if len(data) > MAX_PLAINTEXT_SIZE:
        raise TMSGSizeError(f"data too large to encrypt in one piece ({len(data)} bytes)",
                            size=len(data), limit=MAX_PLAINTEXT_SIZE)

    keys = parse_public_keys(recipients, rpc=rpc)
    if len(keys) > TMSG_MAX_RECIPIENTS:       # pragma: no cover - parse_public_keys enforces it
        raise TMSGFormatError("too many recipients")
    version = select_version(len(keys)) if version is None else version

    cc = load_coincurve()
    AESGCM = _aesgcm()

    if version == TMSG_VERSION_1:
        if len(keys) != 1:
            raise TMSGFormatError("version 0x01 supports exactly one public key")
        eph_pub, key = _wrap_for(cc, keys[0])
        nonce = os.urandom(TMSG_NONCE_SIZE)
        ciphertext = AESGCM(key).encrypt(nonce, data, None)
        return TMSG_MAGIC + bytes([TMSG_VERSION_1]) + eph_pub + nonce + ciphertext

    if version == TMSG_VERSION_2:
        content_key = os.urandom(32)
        message_nonce = os.urandom(TMSG_NONCE_SIZE)
        ciphertext = AESGCM(content_key).encrypt(message_nonce, data, None)
        blocks = []
        for pub in keys:
            eph_pub, key = _wrap_for(cc, pub)
            wrap_nonce = os.urandom(TMSG_NONCE_SIZE)
            blocks.append(eph_pub + wrap_nonce + AESGCM(key).encrypt(wrap_nonce, content_key, None))
        return (TMSG_MAGIC + bytes([TMSG_VERSION_2, len(keys)]) + b"".join(blocks)
                + message_nonce + ciphertext)

    raise TMSGFormatError(f"unsupported version: {version:#04x}")


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

def decrypt(
    payload: Union[bytes, bytearray, memoryview, str],
    private_keys: Union[PrivateKeyLike, Iterable[PrivateKeyLike]],
) -> bytes:
    """
    Decrypt a TMSG payload (v1 or v2) and return the plaintext.

    Args:
        payload:      raw bytes, or a hex string (0x prefix and whitespace allowed).
        private_keys: one private key (32 bytes / 64 hex chars) or several to try in order.

    Raises:
        TMSGFormatError:     not a valid TMSG payload.
        TMSGDecryptionError: none of the keys opens it, or the payload was modified.
        TMSGKeyError:        a private key is invalid.
    """
    raw = _to_bytes(payload)
    parsed = _parse(raw)
    secrets = normalize_private_keys(private_keys)

    cc = load_coincurve()
    AESGCM = _aesgcm()

    if parsed.version == TMSG_VERSION_1:
        try:
            eph = cc.PublicKey(parsed.blocks[0][0])
        except Exception:
            raise TMSGFormatError("invalid ephemeral public key in payload") from None
        for secret in secrets:
            key = _shared_secret(cc.PrivateKey(secret), eph)
            try:
                return AESGCM(key).decrypt(parsed.nonce, parsed.ciphertext, None)
            except Exception:
                continue
        raise TMSGDecryptionError("authentication failed: wrong key or corrupted payload")

    # version 2: find the block this key opens, then open the message with its content key
    for secret in secrets:
        private = cc.PrivateKey(secret)
        for eph_bytes, wrap_nonce, wrapped in parsed.blocks:
            try:
                key = _shared_secret(private, cc.PublicKey(eph_bytes))
                content_key = AESGCM(key).decrypt(wrap_nonce, wrapped, None)
            except Exception:
                continue
            try:
                return AESGCM(content_key).decrypt(parsed.nonce, parsed.ciphertext, None)
            except Exception:
                raise TMSGDecryptionError(
                    "authentication failed: the message was modified or is corrupted"
                ) from None
    raise TMSGDecryptionError("authentication failed: wrong key or corrupted payload")

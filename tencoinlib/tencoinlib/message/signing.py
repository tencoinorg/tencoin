# tencoinlib/message/signing.py
"""
Tencoin Message Signing - Bitcoin Core Compatible

Format:
    Magic Prefix: \x18Tencoin Signed Message:\n
    Output: Base64 (65 bytes) = header (1) || r (32) || s (32)
            header = 31 + recovery_id for a compressed public key
            (27 + recovery_id is accepted when verifying uncompressed keys)

The header byte comes first, exactly as in Bitcoin Core. For compressed keys it
is 31..34, so the Base64 text always starts with 'H' (31) or 'I' (32-34).
"""

import base64
import hashlib
from typing import Optional

try:
    import coincurve
    from coincurve import PublicKey as CoincurvePublicKey
    COINCURVE_AVAILABLE = True
except ImportError:
    COINCURVE_AVAILABLE = False


class MessageSigningError(Exception):
    pass


# ── Magic Prefix ──────────────────────────────────────────────────────────────

MAGIC_PREFIX = b"\x18Tencoin Signed Message:\n"


def _build_message_data(message: str) -> bytes:
    """
    Build message data using the Bitcoin Core message format.

    Format:
        <prefix> + <varint(len)> + <message_bytes>
    """
    msg_bytes = message.encode("utf-8")
    msg_len = len(msg_bytes)

    if msg_len < 253:
        length_prefix = bytes([msg_len])
    elif msg_len < 0x10000:
        length_prefix = b"\xfd" + msg_len.to_bytes(2, "little")
    else:
        length_prefix = b"\xfe" + msg_len.to_bytes(4, "little")

    return MAGIC_PREFIX + length_prefix + msg_bytes


def _double_sha256(data: bytes) -> bytes:
    """Double SHA256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _message_hash(message: str) -> bytes:
    """Return the message hash used for signing."""
    return _double_sha256(_build_message_data(message))


# ── Address Utilities ─────────────────────────────────────────────────────────

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_P2PKH_VERSION = 0x41


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _base58_encode(data: bytes) -> str:
    leading = len(data) - len(data.lstrip(b"\x00"))
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, mod = divmod(num, 58)
        result.append(_BASE58_ALPHABET[mod])
    return _BASE58_ALPHABET[0] * leading + "".join(reversed(result))


def _pubkey_to_p2pkh_address(pubkey_bytes: bytes) -> str:
    """Convert a public key to a P2PKH address."""
    payload = bytes([_P2PKH_VERSION]) + _hash160(pubkey_bytes)
    checksum = _double_sha256(payload)[:4]
    return _base58_encode(payload + checksum)


# ── Sign ──────────────────────────────────────────────────────────────────────

def sign_message(private_key: bytes, message: str) -> str:
    """
    Sign a message using a private key.

    Args:
        private_key: 32-byte private key.
        message: Message string.

    Returns:
        Base64-encoded recoverable signature (65 bytes).

    Raises:
        MessageSigningError
    """
    if not COINCURVE_AVAILABLE:
        raise MessageSigningError(
            "coincurve is required for message signing. "
            "Install with: pip install coincurve"
        )

    if len(private_key) != 32:
        raise MessageSigningError(
            f"Private key must be 32 bytes, got {len(private_key)}"
        )

    try:
        msg_hash = _message_hash(message)
        pk = coincurve.PrivateKey(private_key)

        # Recoverable signature: 64-byte signature + 1-byte recovery ID
        recoverable_sig = pk.sign_recoverable(msg_hash, hasher=None)

        recovery_id = recoverable_sig[64] % 4
        bitcoin_rec_id = 31 + recovery_id

        final_sig = bytes([bitcoin_rec_id]) + recoverable_sig[:64]
        return base64.b64encode(final_sig).decode("ascii")

    except Exception as e:
        raise MessageSigningError(f"Signing failed: {e}") from e


# ── Verify ────────────────────────────────────────────────────────────────────

def verify_message(address: str, message: str, signature_b64: str) -> bool:
    """
    Verify a signed message.

    The public key is recovered from the signature and converted
    to a P2PKH address for comparison.

    Supports both compressed (31-34) and uncompressed (27-30)
    Bitcoin Core signature formats.

    Args:
        address: P2PKH address.
        message: Original message.
        signature_b64: Base64-encoded signature.

    Returns:
        True if the signature is valid, otherwise False.

    Raises:
        MessageSigningError
    """
    if not COINCURVE_AVAILABLE:
        raise MessageSigningError(
            "coincurve is required for message verification. "
            "Install with: pip install coincurve"
        )

    try:
        sig_bytes = base64.b64decode(signature_b64)
    except Exception as e:
        raise MessageSigningError(f"Invalid Base64 signature: {e}") from e

    if len(sig_bytes) != 65:
        raise MessageSigningError(
            f"Signature must be 65 bytes, got {len(sig_bytes)}"
        )

    rec_byte = sig_bytes[0]

    if 31 <= rec_byte <= 34:
        recovery_id = rec_byte - 31
        check_compressed = [True]
    elif 27 <= rec_byte <= 30:
        recovery_id = rec_byte - 27
        check_compressed = [False]
    else:
        raise MessageSigningError(
            f"Invalid recovery byte: {rec_byte} (expected 27-34)"
        )

    verify_sig = sig_bytes[1:65] + bytes([recovery_id])
    msg_hash = _message_hash(message)

    try:
        recovered_pubkey = CoincurvePublicKey.from_signature_and_message(
            verify_sig, msg_hash, hasher=None
        )
    except Exception as e:
        raise MessageSigningError(f"Public key recovery failed: {e}") from e

    for compressed in check_compressed:
        try:
            pubkey_bytes = recovered_pubkey.format(compressed=compressed)
            recovered_address = _pubkey_to_p2pkh_address(pubkey_bytes)
            if recovered_address == address:
                return True
        except Exception:
            continue

    return False


# ── Recover Address ───────────────────────────────────────────────────────────

def recover_address_from_signature(
    message: str,
    signature_b64: str,
) -> Optional[str]:
    """
    Recover the P2PKH address from a signed message.

    Args:
        message: Original message.
        signature_b64: Base64-encoded signature.

    Returns:
        Recovered P2PKH address, or None if recovery fails.
    """
    if not COINCURVE_AVAILABLE:
        raise MessageSigningError(
            "coincurve is required. Install with: pip install coincurve"
        )

    try:
        sig_bytes = base64.b64decode(signature_b64)
        if len(sig_bytes) != 65:
            return None

        rec_byte = sig_bytes[0]
        if 31 <= rec_byte <= 34:
            recovery_id = rec_byte - 31
            compressed = True
        elif 27 <= rec_byte <= 30:
            recovery_id = rec_byte - 27
            compressed = False
        else:
            return None

        verify_sig = sig_bytes[1:65] + bytes([recovery_id])
        msg_hash = _message_hash(message)

        recovered_pubkey = CoincurvePublicKey.from_signature_and_message(
            verify_sig, msg_hash, hasher=None
        )
        pubkey_bytes = recovered_pubkey.format(compressed=compressed)
        return _pubkey_to_p2pkh_address(pubkey_bytes)

    except Exception:
        return None
# tencoinlib/wallet_storage/tce.py
"""
TCE1 — ESP32 wallet blob container format.

This is the *ESP-side* counterpart to the TCW v1 file format (tcw.py).
It exists because ESP32 cannot run Argon2id at any parameter set worth
using (see the KDF note in kdf.py), so the firmware encrypts its NVS
wallet blob with PBKDF2-HMAC-SHA256 instead.

On-wire layout (all integers big-endian):
┌──────────────────────────────────────────────────────────────┐
│ FIXED HEADER  (40 bytes)  == AAD                              │
│   magic        4 bytes   b"TCE1"                              │
│   kdf_id       1 byte    0x02 = PBKDF2-HMAC-SHA256             │
│   cipher_id    1 byte    0x01 = AES-256-GCM                    │
│   iterations   2 bytes   1..10000  (ESP32 ceiling)             │
│   salt         16 bytes                                        │
│   nonce        12 bytes                                        │
│   payload_len  4 bytes   len(ciphertext) + 16 (GCM tag)         │
├──────────────────────────────────────────────────────────────┤
│ ENCRYPTED PAYLOAD  (payload_len bytes)                        │
│   [ ciphertext || 16-byte GCM tag ]                           │
└──────────────────────────────────────────────────────────────┘

AAD = the 40-byte fixed header exactly as written (bytes [0:40)), so any
tampering with magic/kdf_id/cipher_id/iterations/salt/nonce/payload_len
causes AES-GCM authentication to fail at decrypt time — matching the
firmware's tcwblob::decrypt() behaviour.

The *decrypted* payload is NOT JSON. It mirrors the firmware's actual
NVS blob layout byte-for-byte (wsBuildBlob/wsParseBlob), a fixed-offset
binary record, because that's what ships on real devices today and a
JSON re-encode on ESP32 buys nothing but more RAM/CPU and a second
migration to get right:

┌────────────────────────────────────────────────────────────┐
│ off  size  field                                            │
│   0    1   wallet_type      1 = HD, 2 = IMPORTED             │
│   1    1   passphrase_used  0/1 — BIP-39 25th-word flag      │
│   2    1   totp_mask        bit i set => totp slot i in use  │
│   3   30   totp_secrets     3 × 10 raw bytes                 │
│  33   32   private_key      32 raw bytes; all-zero if HD     │
│  65   64   seed             64 raw bytes; all-zero if IMPORTED│
│ 129    2   mnemonic_len     u16 BE                            │
│ 131    N   mnemonic         UTF-8, N = mnemonic_len           │
└────────────────────────────────────────────────────────────┘

pack_esp_payload()/unpack_esp_payload() are the only functions that
know this layout. Every other module (esp_bridge.py, wallet.py) still
works with a plain dict — {"wallet_type": "hd"/"imported", "mnemonic":
str, "seed": hex str, "private_key": hex str, "passphrase_used": bool,
"totp": [hex, hex, hex], "totp_mask": int} — encrypt_esp_blob()/
decrypt_esp_blob() convert to/from the binary record internally, so
that dict-shaped interface does not change.
"""

import struct
import os
from dataclasses import dataclass
from typing import Any, Dict, List

from cryptography.exceptions import InvalidTag

from .kdf import (
    PBKDF2_MAX_ITERATIONS,
    PBKDF2_MIN_ITERATIONS,
    PBKDF2_SALT_LEN,
    KDF_ID_PBKDF2_SHA256,
    derive_key_pbkdf2,
    generate_pbkdf2_salt,
)
from .encryption import (
    CIPHER_ID_AES256_GCM,
    NONCE_LEN,
    TAG_LEN,
    encrypt,
    decrypt,
    generate_nonce,
)

# ---------------------------------------------------------------------------
# Format constants
# ---------------------------------------------------------------------------
MAGIC              = b"TCE1"
FIXED_HEADER_LEN   = 40    # bytes; also the AAD length

# --- binary payload record (wsBuildBlob/wsParseBlob) -----------------------
WALLET_TYPE_HD       = 1
WALLET_TYPE_IMPORTED = 2

_OFF_WALLET_TYPE      = 0
_OFF_PASSPHRASE_USED  = 1
_OFF_TOTP_MASK        = 2
_OFF_TOTP_SECRETS     = 3
_TOTP_SLOT_LEN        = 10
_TOTP_SLOTS           = 3
_TOTP_SECTION_LEN     = _TOTP_SLOT_LEN * _TOTP_SLOTS   # 30
_OFF_PRIVATE_KEY      = _OFF_TOTP_SECRETS + _TOTP_SECTION_LEN   # 33
_PRIVATE_KEY_LEN      = 32
_OFF_SEED             = _OFF_PRIVATE_KEY + _PRIVATE_KEY_LEN      # 65
_SEED_LEN             = 64
_OFF_MNEMONIC_LEN     = _OFF_SEED + _SEED_LEN                    # 129
_MNEMONIC_LEN_LEN     = 2
_OFF_MNEMONIC         = _OFF_MNEMONIC_LEN + _MNEMONIC_LEN_LEN     # 131

RECORD_FIXED_LEN   = _OFF_MNEMONIC   # 131 bytes before the variable mnemonic
MAX_MNEMONIC_LEN   = 512             # generous; longest real BIP-39 phrase is far smaller
MAX_PLAINTEXT_LEN  = RECORD_FIXED_LEN + MAX_MNEMONIC_LEN
MAX_PAYLOAD_LEN    = MAX_PLAINTEXT_LEN + TAG_LEN

# File extension for a TCE1 blob saved to disk (save_esp_blob/load_esp_blob
# below), paralleling ".tcw" for the laptop-side TCW format.
FILE_EXTENSION = ".tce"




# ---------------------------------------------------------------------------
# Header dataclass
# ---------------------------------------------------------------------------

@dataclass
class TCEHeader:
    """Parsed representation of the 40-byte TCE1 fixed header."""
    kdf_id:       int
    cipher_id:    int
    iterations:   int
    salt:         bytes
    nonce:        bytes
    payload_len:  int

    def to_bytes(self) -> bytes:
        """Serialise to the 40-byte wire format (also used as AAD)."""
        if len(self.salt) != PBKDF2_SALT_LEN:
            raise TCEFormatError(f"Salt must be {PBKDF2_SALT_LEN} bytes")
        if len(self.nonce) != NONCE_LEN:
            raise TCEFormatError(f"Nonce must be {NONCE_LEN} bytes")
        return (
            MAGIC
            + struct.pack(
                ">BBH",
                self.kdf_id,
                self.cipher_id,
                self.iterations,
            )
            + self.salt
            + self.nonce
            + struct.pack(">I", self.payload_len)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TCEHeader":
        """Parse the 40-byte fixed header from raw bytes."""
        if len(data) < FIXED_HEADER_LEN:
            raise TCEFormatError(
                f"Blob too short: expected at least {FIXED_HEADER_LEN} bytes, "
                f"got {len(data)}"
            )

        magic = data[:4]
        if magic != MAGIC:
            raise TCEFormatError(
                f"Not a TCE1 blob (magic={magic!r}, expected {MAGIC!r})"
            )

        kdf_id, cipher_id, iterations = struct.unpack(">BBH", data[4:8])
        salt   = data[8:24]
        nonce  = data[24:36]
        (payload_len,) = struct.unpack(">I", data[36:40])

        return cls(
            kdf_id=kdf_id,
            cipher_id=cipher_id,
            iterations=iterations,
            salt=salt,
            nonce=nonce,
            payload_len=payload_len,
        )


# ---------------------------------------------------------------------------
# Binary payload record  (wsBuildBlob / wsParseBlob)
# ---------------------------------------------------------------------------

def pack_esp_payload(payload: Dict[str, Any]) -> bytes:
    """
    Encode a wallet payload dict into the firmware's fixed-offset binary
    record (see the module docstring for the layout).

    Args:
        payload: {
            "wallet_type":      "hd" | "imported",
            "mnemonic":         str,            # "" for imported
            "seed":             hex str,        # "" / 64 hex chars, "" for imported
            "private_key":      hex str,        # "" / 64 hex chars, "" for hd
            "passphrase_used":  bool,            # optional, default False
            "totp":             [hex, hex, hex], # each "" or 20 hex chars (10 bytes)
            "totp_mask":        int,             # optional, default 0
        }

    Returns:
        RECORD_FIXED_LEN + len(mnemonic.encode()) bytes.

    Raises:
        TCEFormatError: Any field has the wrong type/length for its slot.
    """
    wallet_type_str = payload.get("wallet_type")
    if wallet_type_str == "hd":
        wallet_type = WALLET_TYPE_HD
    elif wallet_type_str == "imported":
        wallet_type = WALLET_TYPE_IMPORTED
    else:
        raise TCEFormatError(
            f"Unknown wallet_type: {wallet_type_str!r} (expected 'hd' or 'imported')"
        )

    passphrase_used = 1 if payload.get("passphrase_used") else 0

    totp_mask = payload.get("totp_mask", 0)
    if not (0 <= totp_mask <= 255):
        raise TCEFormatError(f"totp_mask must fit in one byte (0-255), got {totp_mask}")

    totp_slots = payload.get("totp") or ["", "", ""]
    if len(totp_slots) != _TOTP_SLOTS:
        raise TCEFormatError(f"totp must have exactly {_TOTP_SLOTS} slots, got {len(totp_slots)}")
    totp_bytes = b""
    for i, slot in enumerate(totp_slots):
        slot_bytes = _hex_to_fixed_bytes(slot, _TOTP_SLOT_LEN, f"totp[{i}]")
        totp_bytes += slot_bytes

    private_key_hex = payload.get("private_key") or ""
    private_key_bytes = _hex_to_fixed_bytes(private_key_hex, _PRIVATE_KEY_LEN, "private_key")

    seed_hex = payload.get("seed") or ""
    seed_bytes = _hex_to_fixed_bytes(seed_hex, _SEED_LEN, "seed")

    mnemonic = payload.get("mnemonic") or ""
    mnemonic_bytes = mnemonic.encode("utf-8")
    if len(mnemonic_bytes) > MAX_MNEMONIC_LEN:
        raise TCEFormatError(
            f"mnemonic too long: {len(mnemonic_bytes)} bytes (max {MAX_MNEMONIC_LEN})"
        )

    record = (
        struct.pack("BBB", wallet_type, passphrase_used, totp_mask)
        + totp_bytes
        + private_key_bytes
        + seed_bytes
        + struct.pack(">H", len(mnemonic_bytes))
        + mnemonic_bytes
    )
    assert len(record) == RECORD_FIXED_LEN + len(mnemonic_bytes)
    return record


def unpack_esp_payload(record: bytes) -> Dict[str, Any]:
    """
    Decode the firmware's fixed-offset binary record back into a wallet
    payload dict (inverse of pack_esp_payload()).

    Raises:
        TCEFormatError: Record is too short, declares a mnemonic_len that
                        doesn't match the remaining bytes, or has an
                        unrecognised wallet_type byte.
    """
    if len(record) < RECORD_FIXED_LEN:
        raise TCEFormatError(
            f"Payload record too short: expected at least {RECORD_FIXED_LEN} "
            f"bytes, got {len(record)}"
        )

    wallet_type_byte = record[_OFF_WALLET_TYPE]
    if wallet_type_byte == WALLET_TYPE_HD:
        wallet_type_str = "hd"
    elif wallet_type_byte == WALLET_TYPE_IMPORTED:
        wallet_type_str = "imported"
    else:
        raise TCEFormatError(f"Unknown wallet_type byte: {wallet_type_byte:#04x}")

    passphrase_used = bool(record[_OFF_PASSPHRASE_USED])
    totp_mask       = record[_OFF_TOTP_MASK]

    totp_raw = record[_OFF_TOTP_SECRETS:_OFF_TOTP_SECRETS + _TOTP_SECTION_LEN]
    totp = []
    for i in range(_TOTP_SLOTS):
        slot_raw = totp_raw[i * _TOTP_SLOT_LEN:(i + 1) * _TOTP_SLOT_LEN]
        totp.append("" if slot_raw == b"\x00" * _TOTP_SLOT_LEN else slot_raw.hex())

    private_key_raw = record[_OFF_PRIVATE_KEY:_OFF_PRIVATE_KEY + _PRIVATE_KEY_LEN]
    private_key_hex = "" if private_key_raw == b"\x00" * _PRIVATE_KEY_LEN else private_key_raw.hex()

    seed_raw = record[_OFF_SEED:_OFF_SEED + _SEED_LEN]
    seed_hex = "" if seed_raw == b"\x00" * _SEED_LEN else seed_raw.hex()

    (mnemonic_len,) = struct.unpack(">H", record[_OFF_MNEMONIC_LEN:_OFF_MNEMONIC])
    mnemonic_bytes = record[_OFF_MNEMONIC:_OFF_MNEMONIC + mnemonic_len]
    if len(mnemonic_bytes) != mnemonic_len:
        raise TCEFormatError(
            f"Truncated record: mnemonic_len={mnemonic_len} but only "
            f"{len(mnemonic_bytes)} bytes follow"
        )
    if len(record) != _OFF_MNEMONIC + mnemonic_len:
        raise TCEFormatError(
            f"Trailing bytes after mnemonic: record is {len(record)} bytes, "
            f"expected {_OFF_MNEMONIC + mnemonic_len}"
        )
    try:
        mnemonic = mnemonic_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TCEFormatError(f"mnemonic is not valid UTF-8: {exc}") from exc

    return {
        "wallet_type":     wallet_type_str,
        "mnemonic":        mnemonic,
        "seed":            seed_hex,
        "private_key":     private_key_hex,
        "passphrase_used": passphrase_used,
        "totp":            totp,
        "totp_mask":       totp_mask,
    }


def _hex_to_fixed_bytes(hex_str: str, length: int, field_name: str) -> bytes:
    """Decode a hex string into exactly `length` bytes; "" -> all-zero."""
    if hex_str == "":
        return b"\x00" * length
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError as exc:
        raise TCEFormatError(f"{field_name} is not valid hex: {exc}") from exc
    if len(raw) != length:
        raise TCEFormatError(
            f"{field_name} must be {length} bytes ({length * 2} hex chars) "
            f"or empty, got {len(raw)} bytes"
        )
    return raw


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TCEError(Exception):
    """Base exception for TCE1 blob format errors."""


class TCEFormatError(TCEError):
    """Raised when the blob structure is invalid or unrecognised."""


class TCEAuthError(TCEError):
    """
    Raised when AES-GCM authentication fails — wrong password,
    corrupted blob, or tampered header/payload.
    """


class TCEVersionError(TCEError):
    """Raised when the KDF/cipher IDs are not the ones this module supports."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt_esp_blob(
    payload: Dict[str, Any],
    password: str,
    iterations: int = PBKDF2_MAX_ITERATIONS,
) -> bytes:
    """
    Encrypt *payload* with *password* into a TCE1 blob (ESP32 format).

    Args:
        payload:    Wallet payload dict — see pack_esp_payload() for the
                    exact schema (wallet_type/mnemonic/seed/private_key/
                    passphrase_used/totp/totp_mask). Encoded as the
                    firmware's fixed-offset binary record, not JSON.
        password:   User passphrase. UTF-8, no normalisation — matches
                    the firmware, which accepts raw UTF-8 passwords
                    (including non-ASCII).
        iterations: PBKDF2 iteration count, 1..10000 (ESP32 ceiling).
                    Stored in the header, so old blobs made with a lower
                    count keep working even if the default is raised
                    later.

    Returns:
        Raw TCE1 blob bytes, ready to send to / store on the ESP32.

    Raises:
        TCEError: If payload is too large, malformed, or iterations are
                  out of range.
    """
    if not (PBKDF2_MIN_ITERATIONS <= iterations <= PBKDF2_MAX_ITERATIONS):
        raise TCEFormatError(
            f"iterations must be between {PBKDF2_MIN_ITERATIONS} and "
            f"{PBKDF2_MAX_ITERATIONS} (ESP32 ceiling), got {iterations}"
        )

    plaintext: bytes = pack_esp_payload(payload)
    if len(plaintext) > MAX_PLAINTEXT_LEN:
        raise TCEFormatError(
            f"Payload too large for the ESP32 blob format: {len(plaintext)} "
            f"bytes (max {MAX_PLAINTEXT_LEN})"
        )

    salt  = generate_pbkdf2_salt()
    nonce = generate_nonce()
    key   = derive_key_pbkdf2(password, salt, iterations)

    ciphertext_len_estimate = len(plaintext) + TAG_LEN

    header = TCEHeader(
        kdf_id=KDF_ID_PBKDF2_SHA256,
        cipher_id=CIPHER_ID_AES256_GCM,
        iterations=iterations,
        salt=salt,
        nonce=nonce,
        payload_len=ciphertext_len_estimate,
    )
    aad = header.to_bytes()

    ciphertext = encrypt(key, nonce, plaintext, aad)
    assert len(ciphertext) == ciphertext_len_estimate, (
        f"Ciphertext length mismatch: expected {ciphertext_len_estimate}, "
        f"got {len(ciphertext)}"
    )
    _zeroize(key)

    return aad + ciphertext


def decrypt_esp_blob(blob: bytes, password: str) -> Dict[str, Any]:
    """
    Decrypt a TCE1 blob (ESP32 format), returning the wallet payload dict.

    Args:
        blob:     Raw TCE1 bytes, as read from the ESP32 NVS export
                  endpoint (after hex/base64-decoding the transport
                  encoding).
        password: The ESP wallet's passphrase.

    Returns:
        Dict with the decrypted wallet payload.

    Raises:
        TCEFormatError:  Blob is not a valid TCE1 container, or its
                         declared length doesn't match the actual data
                         (rejects truncated/padded blobs).
        TCEVersionError: Unknown kdf_id/cipher_id.
        TCEAuthError:    Wrong password or the blob is corrupted/tampered.
    """
    header = TCEHeader.from_bytes(blob[:FIXED_HEADER_LEN])
    aad    = blob[:FIXED_HEADER_LEN]

    _validate_header(header)

    ciphertext = blob[FIXED_HEADER_LEN:]
    if len(ciphertext) != header.payload_len:
        raise TCEFormatError(
            f"Blob length mismatch: header declares payload_len="
            f"{header.payload_len}, but {len(ciphertext)} bytes follow "
            f"the header"
        )

    key = derive_key_pbkdf2(password, header.salt, header.iterations)
    try:
        plaintext = decrypt(key, header.nonce, ciphertext, aad)
    except InvalidTag:
        raise TCEAuthError(
            "ESP wallet authentication failed: wrong password or corrupted blob."
        )
    finally:
        _zeroize(key)

    try:
        payload = unpack_esp_payload(plaintext)
    except TCEFormatError:
        raise
    except (struct.error, UnicodeDecodeError) as exc:
        raise TCEFormatError(f"Payload record is malformed: {exc}") from exc

    return payload


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _validate_header(header: TCEHeader) -> None:
    if header.kdf_id != KDF_ID_PBKDF2_SHA256:
        raise TCEVersionError(f"Unknown KDF ID: {header.kdf_id:#04x}")
    if header.cipher_id != CIPHER_ID_AES256_GCM:
        raise TCEVersionError(f"Unknown cipher ID: {header.cipher_id:#04x}")
    if not (PBKDF2_MIN_ITERATIONS <= header.iterations <= PBKDF2_MAX_ITERATIONS):
        raise TCEFormatError(
            f"Iteration count out of range: {header.iterations} "
            f"(must be {PBKDF2_MIN_ITERATIONS}..{PBKDF2_MAX_ITERATIONS})"
        )
    if len(header.salt) != PBKDF2_SALT_LEN:
        raise TCEFormatError(f"Unexpected salt length: {len(header.salt)}")
    if len(header.nonce) != NONCE_LEN:
        raise TCEFormatError(f"Unexpected nonce length: {len(header.nonce)}")
    if header.payload_len == 0 or header.payload_len > MAX_PAYLOAD_LEN:
        raise TCEFormatError(f"Payload length out of range: {header.payload_len}")


def _zeroize(key: bytes) -> None:
    """Best-effort zeroization (see tcw.py._zeroize for caveats)."""
    if isinstance(key, bytearray):
        for i in range(len(key)):
            key[i] = 0
    del key


# ---------------------------------------------------------------------------
# File I/O  (.tce)
# ---------------------------------------------------------------------------
#
# The TCE1 blob itself is protocol-agnostic bytes (it's normally moved as
# hex over HTTP to/from the ESP32's own endpoints). These two functions
# are only for the common case of stashing a copy of that blob on disk in
# between — e.g. downloaded from GET /api/wallet/export before running
# esp_blob_to_tcw_file(), or built by tcw_file_to_esp_blob() before being
# uploaded via POST /api/wallet/import.

def _resolve_esp_filepath(filepath: str) -> str:
    """
    Resolve the actual path of a .tce file, mirroring Wallet._resolve_filepath
    for .tcw:
      - Explicit ".tce" extension (case-insensitive) → used as-is.
      - No extension → try the bare name first, then with ".tce" appended.
    """
    has_extension = filepath.lower().endswith(FILE_EXTENSION)

    if has_extension:
        return filepath

    if os.path.exists(filepath):
        return filepath

    with_ext = filepath + FILE_EXTENSION
    if os.path.exists(with_ext):
        return with_ext

    raise FileNotFoundError(
        f"ESP blob file not found: '{filepath}' or '{with_ext}'"
    )


def save_esp_blob(filepath: str, blob: bytes) -> str:
    """
    Write a raw TCE1 blob to disk as a .tce file.

    A ".tce" extension is appended if `filepath` doesn't already end
    with one (case-insensitive) — same convention as Wallet.save()
    appending ".tcw".

    Args:
        filepath: Destination path (e.g. "esp_wallet" or "esp_wallet.tce").
        blob:     Raw TCE1 bytes, e.g. from encrypt_esp_blob() or
                  bytes.fromhex(blob_hex) from the ESP32's export endpoint.

    Returns:
        The path actually written to.
    """
    if not filepath.lower().endswith(FILE_EXTENSION):
        filepath = filepath + FILE_EXTENSION

    with open(filepath, "wb") as f:
        f.write(blob)

    return filepath


def load_esp_blob(filepath: str) -> bytes:
    """
    Read a raw TCE1 blob from a .tce file (extension resolved
    automatically if omitted — see _resolve_esp_filepath).

    Note this only reads the bytes; it does not decrypt or validate the
    TCE1 structure. Pass the result to decrypt_esp_blob() (directly, or
    via esp_blob_to_tcw_file()) for that.

    Args:
        filepath: Path to a .tce file (extension optional).

    Returns:
        Raw blob bytes.

    Raises:
        FileNotFoundError: Neither `filepath` nor `filepath + ".tce"` exists.
    """
    resolved = _resolve_esp_filepath(filepath)
    with open(resolved, "rb") as f:
        return f.read()

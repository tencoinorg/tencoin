# tencoinlib/wallet_storage/esp_bridge.py
"""
ESP32 <-> laptop wallet bridge.

The ESP32 firmware and tencoinlib both protect the same wallet secrets,
but neither the on-wire encoding nor the KDF matches byte-for-byte (see
tce.py vs tcw.py). This module is the only place that knows how to
translate between:

  ESP payload dict (decoded from the firmware's binary NVS record —
  see tce.py's pack_esp_payload/unpack_esp_payload for the exact
  fixed-offset layout; this is NOT JSON on the wire, only a dict once
  in Python):
      {
        "wallet_type":      "hd" | "imported",
        "mnemonic":         str,   # hd: filled | imported: ""
        "seed":             str,   # hd: 64-char hex | imported: ""
        "private_key":      str,   # hd: "" | imported: 64-char hex (32 bytes)
        "passphrase_used":  bool,  # BIP-39 25th-word flag
        "totp":             [str, str, str],   # 3 x 10-byte hex slots
        "totp_mask":        int,
      }

  tencoinlib TCW payload (see Wallet._to_payload / _load_from_payload):
      {
        "format": "TCW", "version": 1,
        "wallet_type": "hd" | "xprv" | "privkey" | "xpub",
        "mnemonic": str | None, "seed_hex": str | None,
        "imported_xprv": str | None, "raw_private_key_hex": str | None,
        "imported_xpub": str | None,
        "address": str, "public_key": str, "derivation_path": str,
        "account_index": int, "change_index": int, "address_index": int,
        "is_watch_only": bool,
      }

Conversion is always done via this shared plaintext payload — never by
copying ciphertext bytes across formats (different KDF, different key,
different AAD). See the module docstrings of tce.py and tcw.py for the
wire formats on each side.

Only two TCW wallet types can round-trip to ESP, because ESP only knows
two wallet shapes:
  - "hd"      (mnemonic + seed, full HD tree)              -> ESP "hd"
  - "privkey" (a single raw key, no chain code, no HD tree) -> ESP "imported"
"xprv" (an imported *extended* key with a chain code) and "xpub"
(watch-only, no secrets at all) have no ESP equivalent and are rejected
with a clear error rather than silently losing the chain code or
exporting nothing.
"""

from typing import Any, Dict, List, Optional, Union

from .kdf import PBKDF2_MAX_ITERATIONS
from .tce import encrypt_esp_blob, decrypt_esp_blob, load_esp_blob, save_esp_blob
from .tcw import save_wallet, load_wallet
from ..keys.bip39 import validate_mnemonic, mnemonic_to_seed
from ..constants import DERIVATION_PATH

# Keys stashed inside the TCW payload to carry ESP-only fields (2FA TOTP
# slots, the BIP-39 passphrase-used flag) through a round trip that
# passes through a .tcw file. tencoinlib itself never reads or writes
# these; they only exist so that ESP -> laptop -> ESP doesn't silently
# drop them.
_ESP_TOTP_KEY             = "esp_totp"
_ESP_TOTP_MASK_KEY        = "esp_totp_mask"
_ESP_PASSPHRASE_USED_KEY  = "esp_passphrase_used"

_DEFAULT_TOTP      = ["", "", ""]
_DEFAULT_TOTP_MASK = 0


class ESPBridgeError(Exception):
    """Raised for schema/validation problems converting ESP <-> TCW payloads."""


# ---------------------------------------------------------------------------
# Payload schema translation
# ---------------------------------------------------------------------------

def esp_payload_to_tcw_payload(esp_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert an ESP wallet JSON payload into a tencoinlib TCW payload dict.

    The result is suitable for wallet_storage.tcw.save_wallet() and, once
    written to a .tcw file, for the ordinary Wallet.load(path).unlock(pw)
    flow — address/public_key are recomputed by Wallet._load_from_payload
    from the secret material, so leaving them blank here is intentional.

    Raises:
        ESPBridgeError: If wallet_type is missing/unknown, or required
                        fields for that type are missing.
    """
    wallet_type = esp_payload.get("wallet_type")

    base = {
        "format": "TCW",
        "version": 1,
        "imported_xprv": None,
        "imported_xpub": None,
        "address": "",
        "public_key": "",
        "account_index": 0,
        "change_index": 0,
        "address_index": 0,
        "is_watch_only": False,
    }

    if wallet_type == "hd":
        mnemonic = esp_payload.get("mnemonic") or ""
        seed_hex = esp_payload.get("seed") or ""
        if not mnemonic or not seed_hex:
            raise ESPBridgeError(
                "ESP payload wallet_type='hd' is missing mnemonic and/or seed"
            )
        base.update({
            "wallet_type":         "hd",
            "mnemonic":            mnemonic,
            "seed_hex":            seed_hex,
            "raw_private_key_hex": None,
            "derivation_path":     DERIVATION_PATH,
        })

    elif wallet_type == "imported":
        private_key_hex = esp_payload.get("private_key") or ""
        if not private_key_hex:
            raise ESPBridgeError(
                "ESP payload wallet_type='imported' is missing private_key"
            )
        base.update({
            "wallet_type":         "privkey",
            "mnemonic":            None,
            "seed_hex":            None,
            "raw_private_key_hex": private_key_hex,
            "derivation_path":     "",
        })

    else:
        raise ESPBridgeError(
            f"Unknown ESP wallet_type: {wallet_type!r} (expected 'hd' or 'imported')"
        )

    # Carry the 2FA slots and passphrase flag through opaquely so
    # re-exporting to ESP later doesn't lose them. tencoinlib's own
    # Wallet ignores unknown keys.
    base[_ESP_TOTP_KEY]            = esp_payload.get("totp", _DEFAULT_TOTP)
    base[_ESP_TOTP_MASK_KEY]       = esp_payload.get("totp_mask", _DEFAULT_TOTP_MASK)
    base[_ESP_PASSPHRASE_USED_KEY] = bool(esp_payload.get("passphrase_used", False))

    return base


def tcw_payload_to_esp_payload(
    tcw_payload: Dict[str, Any],
    totp: Optional[List[str]] = None,
    totp_mask: Optional[int] = None,
    passphrase_used: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Convert a tencoinlib TCW payload dict into an ESP wallet payload dict.

    Args:
        tcw_payload:     The dict returned by wallet_storage.tcw.load_wallet()
                         (or Wallet._to_payload()).
        totp:            Explicit 2FA slots to embed (overrides any carried
                         via esp_totp from a previous ESP->TCW conversion).
        totp_mask:       Explicit 2FA slot-enabled bitmask (same override rule).
        passphrase_used: Explicit BIP-39 25th-word flag (overrides any
                         carried via esp_passphrase_used). Defaults to
                         False for a wallet built directly on the laptop
                         (tencoinlib's own mnemonic/seed generation
                         doesn't use a BIP-39 passphrase).

    Returns:
        ESP-schema payload dict, ready for tce.encrypt_esp_blob() /
        tce.pack_esp_payload().

    Raises:
        ESPBridgeError: If the TCW wallet_type has no ESP equivalent
                        ("xprv" — chain code would be lost silently;
                        "xpub" — watch-only, no secrets to export at all),
                        or is unrecognised.
    """
    wallet_type = tcw_payload.get("wallet_type")

    if wallet_type == "hd":
        mnemonic = tcw_payload.get("mnemonic") or ""
        seed_hex = tcw_payload.get("seed_hex") or ""
        if not mnemonic or not seed_hex:
            raise ESPBridgeError(
                "TCW payload wallet_type='hd' is missing mnemonic and/or seed_hex"
            )
        esp_payload = {
            "wallet_type":  "hd",
            "mnemonic":     mnemonic,
            "seed":         seed_hex,
            "private_key":  "",
        }

    elif wallet_type == "privkey":
        raw_hex = tcw_payload.get("raw_private_key_hex") or ""
        if not raw_hex:
            raise ESPBridgeError(
                "TCW payload wallet_type='privkey' is missing raw_private_key_hex"
            )
        esp_payload = {
            "wallet_type":  "imported",
            "mnemonic":     "",
            "seed":         "",
            "private_key":  raw_hex,
        }

    elif wallet_type == "xprv":
        raise ESPBridgeError(
            "TCW wallet_type='xprv' (an imported extended key) cannot be "
            "exported to ESP32: ESP only understands a full HD wallet "
            "(mnemonic+seed) or a single raw imported key, and flattening "
            "an xprv to one key would silently discard its chain code and "
            "every other address it can derive. Derive the one child key "
            "you actually want, build a 'privkey' wallet with "
            "Wallet.from_private_key(...), and export that instead."
        )

    elif wallet_type == "xpub":
        raise ESPBridgeError(
            "TCW wallet_type='xpub' is a watch-only wallet: it holds no "
            "private keys or mnemonic, so there is nothing to export to "
            "the ESP32 (which always needs signing secrets on-device)."
        )

    else:
        raise ESPBridgeError(f"Unknown TCW wallet_type: {wallet_type!r}")

    esp_payload["totp"] = (
        totp if totp is not None else tcw_payload.get(_ESP_TOTP_KEY, _DEFAULT_TOTP)
    )
    esp_payload["totp_mask"] = (
        totp_mask if totp_mask is not None
        else tcw_payload.get(_ESP_TOTP_MASK_KEY, _DEFAULT_TOTP_MASK)
    )
    esp_payload["passphrase_used"] = bool(
        passphrase_used if passphrase_used is not None
        else tcw_payload.get(_ESP_PASSPHRASE_USED_KEY, False)
    )

    return esp_payload



def validate_esp_payload(esp_payload: Dict[str, Any]) -> None:
    """
    Validate an ESP payload's internal consistency before it is trusted
    (mirrors the checks ESP_WALLET_STRUCTURE.md §3.2 step 3 asks the
    firmware to run before overwriting NVS).

    Raises:
        ESPBridgeError: If the payload is inconsistent for its declared
                        wallet_type.
    """
    wallet_type = esp_payload.get("wallet_type")

    if wallet_type == "hd":
        mnemonic = esp_payload.get("mnemonic") or ""
        seed_hex = esp_payload.get("seed") or ""
        private_key = esp_payload.get("private_key") or ""
        passphrase_used = bool(esp_payload.get("passphrase_used", False))
        if private_key:
            raise ESPBridgeError("hd payload must have an empty private_key")
        if not validate_mnemonic(mnemonic):
            raise ESPBridgeError("hd payload mnemonic failed BIP-39 checksum validation")
        if passphrase_used:
            # The firmware records only that a 25th-word passphrase was
            # used, never the passphrase text itself, so the seed cannot
            # be recomputed here — just check it's a well-formed 64-byte
            # value and trust the device that produced it.
            try:
                seed_bytes = bytes.fromhex(seed_hex)
            except ValueError as exc:
                raise ESPBridgeError(f"hd payload seed is not valid hex: {exc}") from exc
            if len(seed_bytes) != 64:
                raise ESPBridgeError(
                    f"hd payload seed must be 64 bytes, got {len(seed_bytes)}"
                )
        else:
            try:
                expected_seed = mnemonic_to_seed(mnemonic).hex()
            except Exception as exc:  # pragma: no cover - defensive
                raise ESPBridgeError(f"Could not derive seed from mnemonic: {exc}") from exc
            if seed_hex.lower() != expected_seed.lower():
                raise ESPBridgeError(
                    "hd payload seed does not match PBKDF2(mnemonic) — payload is inconsistent"
                )

    elif wallet_type == "imported":
        mnemonic = esp_payload.get("mnemonic") or ""
        seed_hex = esp_payload.get("seed") or ""
        private_key = esp_payload.get("private_key") or ""
        if mnemonic or seed_hex:
            raise ESPBridgeError("imported payload must have empty mnemonic and seed")
        try:
            key_bytes = bytes.fromhex(private_key)
        except ValueError as exc:
            raise ESPBridgeError(f"imported payload private_key is not valid hex: {exc}") from exc
        if len(key_bytes) != 32:
            raise ESPBridgeError(
                f"imported payload private_key must be 32 bytes, got {len(key_bytes)}"
            )

    else:
        raise ESPBridgeError(
            f"Unknown ESP wallet_type: {wallet_type!r} (expected 'hd' or 'imported')"
        )


# ---------------------------------------------------------------------------
# High-level bridge: TCE1 blob <-> .tcw file
# ---------------------------------------------------------------------------

def esp_blob_to_tcw_file(
    blob: Union[bytes, str],
    esp_password: str,
    out_path: str,
    tcw_password: str,
) -> str:
    """
    Extract FROM ESP: decrypt a TCE1 blob and write it out as a regular
    Argon2id-encrypted .tcw file that Wallet.load(path).unlock(pw) can
    open normally.

    Args:
        blob:         Raw TCE1 bytes read from the ESP32
                       (GET /api/wallet/export), OR a path to a .tce
                       file previously written with save_esp_blob()
                       (extension resolved the same way as .tcw).
        esp_password: The password that protects the ESP wallet.
        out_path:     Destination .tcw path.
        tcw_password: Password for the *new* .tcw file — may differ from
                       esp_password.

    Returns:
        The path the .tcw file was written to.

    Raises:
        FileNotFoundError: `blob` was a path and no .tce file was found.
        TCEAuthError:   Wrong esp_password, or the blob is corrupted/tampered.
        TCEFormatError: blob is not a valid TCE1 container.
        ESPBridgeError: Decrypted payload is malformed or inconsistent.
    """
    if isinstance(blob, str):
        blob = load_esp_blob(blob)

    esp_payload = decrypt_esp_blob(blob, esp_password)
    validate_esp_payload(esp_payload)
    tcw_payload = esp_payload_to_tcw_payload(esp_payload)
    save_wallet(out_path, tcw_payload, tcw_password)
    return out_path


def tcw_file_to_esp_blob(
    tcw_path: str,
    tcw_password: str,
    esp_password: str,
    iterations: int = PBKDF2_MAX_ITERATIONS,
    totp: Optional[List[str]] = None,
    totp_mask: Optional[int] = None,
    out_path: Optional[str] = None,
) -> bytes:
    """
    Import FROM laptop: decrypt a .tcw file and re-encrypt its payload as
    a TCE1 blob the ESP32 firmware can store in NVS
    (POST /api/wallet/import).

    Args:
        tcw_path:     Path to the source .tcw file.
        tcw_password: Password for that .tcw file.
        esp_password: Password to protect the new ESP blob — may differ
                       from tcw_password.
        iterations:   PBKDF2 iteration count for the ESP blob (1..10000;
                       default is the ESP32 ceiling). Measure actual
                       unlock time on real hardware before raising this
                       close to the ceiling.
        totp:         Optional 2FA slots to embed (see
                       tcw_payload_to_esp_payload).
        totp_mask:    Optional 2FA slot-enabled bitmask.
        out_path:     Optional destination to also save the blob as a
                       .tce file (via save_esp_blob) — handy if you'd
                       rather copy a file to the device than paste hex.
                       The blob is still returned either way.

    Returns:
        Raw TCE1 blob bytes (send blob.hex() to the ESP32, or use
        out_path to get a .tce file instead).

    Raises:
        TCWAuthError:   Wrong tcw_password, or the file is corrupted/tampered.
        TCWFormatError: File is not a valid TCW container.
        ESPBridgeError: The TCW wallet_type has no ESP equivalent
                        (see tcw_payload_to_esp_payload), or the source
                        payload is malformed.
    """
    tcw_payload = load_wallet(tcw_path, tcw_password)
    esp_payload = tcw_payload_to_esp_payload(tcw_payload, totp=totp, totp_mask=totp_mask)
    validate_esp_payload(esp_payload)
    blob = encrypt_esp_blob(esp_payload, esp_password, iterations=iterations)

    if out_path is not None:
        save_esp_blob(out_path, blob)

    return blob

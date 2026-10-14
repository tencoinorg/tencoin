# tencoinlib/wallet_storage/__init__.py
"""
TCW wallet storage subsystem.

Provides the TCW v1 binary container format with:
  - Argon2id password-based key derivation  (kdf.py)
  - AES-256-GCM authenticated encryption    (encryption.py)
  - TCW binary container format             (tcw.py)

Also provides the ESP32-side counterpart and the bridge between them:
  - TCE1 blob format (PBKDF2-HMAC-SHA256 + AES-256-GCM)  (tce.py)
  - ESP <-> TCW payload/schema translation and file/blob
    glue (esp_bridge.py): esp_blob_to_tcw_file / tcw_file_to_esp_blob

Public surface:
    save_wallet(filepath, payload_dict, password)
    load_wallet(filepath, password) -> dict
    read_header(filepath) -> TCWHeader

    encrypt_esp_blob(payload_dict, password, iterations=10000) -> bytes
    decrypt_esp_blob(blob, password) -> dict
    save_esp_blob(filepath, blob) -> str          # writes a .tce file
    load_esp_blob(filepath) -> bytes              # reads a .tce file

    esp_blob_to_tcw_file(blob, esp_password, out_path, tcw_password) -> str
    tcw_file_to_esp_blob(tcw_path, tcw_password, esp_password, iterations=10000) -> bytes
"""

from .tcw import (
    save_wallet, load_wallet, read_header, TCWHeader,
    TCWError, TCWFormatError, TCWAuthError, TCWVersionError,
)
from .tce import (
    encrypt_esp_blob, decrypt_esp_blob, TCEHeader,
    save_esp_blob, load_esp_blob,
    TCEError, TCEFormatError, TCEAuthError, TCEVersionError,
)
from .esp_bridge import (
    esp_blob_to_tcw_file, tcw_file_to_esp_blob,
    esp_payload_to_tcw_payload, tcw_payload_to_esp_payload,
    validate_esp_payload, ESPBridgeError,
)

__all__ = [
    "save_wallet", "load_wallet", "read_header", "TCWHeader",
    "TCWError", "TCWFormatError", "TCWAuthError", "TCWVersionError",

    "encrypt_esp_blob", "decrypt_esp_blob", "TCEHeader",
    "save_esp_blob", "load_esp_blob",
    "TCEError", "TCEFormatError", "TCEAuthError", "TCEVersionError",

    "esp_blob_to_tcw_file", "tcw_file_to_esp_blob",
    "esp_payload_to_tcw_payload", "tcw_payload_to_esp_payload",
    "validate_esp_payload", "ESPBridgeError",
]
"""
TMSG - Tencoin Message.

End-to-end encryption of messages, files and folders to one or many public keys
(ECDH secp256k1 + AES-256-GCM), off-chain, or on-chain inside an OP_RETURN output.

    from tencoinlib import tmsg

    # off-chain
    payload = tmsg.encrypt(b"secret", recipient_pubkey)        # v1 for one key, v2 for several
    tmsg.decrypt(payload, private_key)
    tmsg.encrypt_text("hello", [pub1, pub2], as_hex=True)
    tmsg.encrypt_file("report.pdf", pub);  tmsg.decrypt_file("report.pdf.enc", priv)
    tmsg.encrypt_folder("docs", pub);      tmsg.decrypt_folder("docs.zip.enc", priv)

    # on-chain (1 Teno + OP_RETURN + change)
    tx = tmsg.build_tmsg_transaction(utxos, "tc1q...", "hello", recipients=pub, change_address=...)
    raw = tx.sign(private_keys).raw_transaction
    tmsg.decrypt_transaction(raw, priv)

Version 1 = exactly one recipient key, version 2 = 2..255 keys (any ONE private key
decrypts). The version is chosen automatically.
"""

from .errors import (
    TMSGError, TMSGKeyError, TMSGFormatError, TMSGDecryptionError,
    TMSGSizeError, TMSGDependencyError,
)
from .keys import (
    normalize_public_key, parse_public_keys, normalize_private_key,
    public_key_from_private_key,
)
from .crypto import (
    encrypt, decrypt, inspect, is_tmsg, overhead, max_plaintext, select_version, TMSGInfo,
)
from .files import (
    encrypt_text, decrypt_text,
    encrypt_file, decrypt_file, encrypt_folder, decrypt_folder,
    FileResult, FolderResult,
)
from .onchain import (
    build_tmsg_transaction, TMSGTransaction, extract_tmsg_payloads, decrypt_transaction,
    DecryptedMessage, OnChainTMSG, parse_op_return, op_return_script_length,
)
from ..constants import (
    TMSG_MAGIC, TMSG_VERSION_1, TMSG_VERSION_2, TMSG_MAX_RECIPIENTS, TMSG_MIN_PAYMENT,
    OP_RETURN_MAX_DATA,
)

__all__ = [
    "TMSGError", "TMSGKeyError", "TMSGFormatError", "TMSGDecryptionError",
    "TMSGSizeError", "TMSGDependencyError",
    "normalize_public_key", "parse_public_keys", "normalize_private_key",
    "public_key_from_private_key",
    "encrypt", "decrypt", "inspect", "is_tmsg", "overhead", "max_plaintext",
    "select_version", "TMSGInfo",
    "encrypt_text", "decrypt_text",
    "encrypt_file", "decrypt_file", "encrypt_folder", "decrypt_folder",
    "FileResult", "FolderResult",
    "build_tmsg_transaction", "TMSGTransaction", "extract_tmsg_payloads",
    "decrypt_transaction", "DecryptedMessage", "OnChainTMSG", "parse_op_return",
    "op_return_script_length",
    "TMSG_MAGIC", "TMSG_VERSION_1", "TMSG_VERSION_2", "TMSG_MAX_RECIPIENTS",
    "TMSG_MIN_PAYMENT", "OP_RETURN_MAX_DATA",
]

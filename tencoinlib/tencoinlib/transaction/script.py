from typing import List

from ..utils import hash160, sha256, base58check_encode, bech32_encode, convert_bits
from ..constants import MAINNET_HRP, P2PKH_VERSION, P2SH_VERSION

# OP codes (Bitcoin script)
OP_0 = 0x00
OP_1 = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_16 = 0x60
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_EQUAL = 0x87
OP_CHECKMULTISIG = 0xAE


class ScriptError(Exception):
    """Script-related errors"""
    pass


def build_p2pkh_script(pubkey: bytes) -> bytes:
    """
    Build P2PKH redeem script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG.

    Args:
        pubkey: 33-byte compressed public key

    Returns:
        Redeem script bytes (used as redeem_script for P2SH or as scriptPubKey for P2PKH)
    """
    if len(pubkey) != 33:
        raise ScriptError(f"Compressed pubkey must be 33 bytes, got {len(pubkey)}")
    h = hash160(pubkey)
    return bytes([OP_DUP, OP_HASH160, 0x14]) + h + bytes([OP_EQUALVERIFY, OP_CHECKSIG])


def build_multisig_script(m: int, pubkeys: List[bytes], sort_pubkeys: bool = True) -> bytes:
    """
    Build m-of-n multisig redeem script (standard form).

    Format: OP_m <len pub1> <pub1> ... <len pubn> <pubn> OP_n OP_CHECKMULTISIG
    Pubkeys are compressed (33 bytes). For canonical output, pubkeys are sorted.

    Args:
        m: Required signatures (1..16)
        pubkeys: List of 33-byte compressed public keys (n = len(pubkeys), 1..16)
        sort_pubkeys: If True, sort pubkeys for canonical/canonicalized form (recommended)

    Returns:
        Redeem script bytes (use with script_to_p2sh_address or script_to_p2wsh_address)
    """
    if not (1 <= m <= 16 and 1 <= len(pubkeys) <= 16 and m <= len(pubkeys)):
        raise ScriptError("m and n must be 1..16 and m <= n")
    for p in pubkeys:
        if len(p) != 33:
            raise ScriptError(f"Each pubkey must be 33 bytes, got {len(p)}")
    ordered = sorted(pubkeys) if sort_pubkeys else list(pubkeys)
    n = len(ordered)
    script = bytes([0x50 + m])  # OP_m
    for pub in ordered:
        script += bytes([len(pub)]) + pub
    script += bytes([0x50 + n, OP_CHECKMULTISIG])
    return script


def script_to_p2sh_address(script: bytes, version: int = P2SH_VERSION) -> str:
    """
    Encode a redeem script as P2SH address (M...).

    Args:
        script: Redeem script bytes
        version: P2SH version byte (default mainnet 0x32)

    Returns:
        Base58Check P2SH address
    """
    if not script:
        raise ScriptError("Script cannot be empty")
    payload = hash160(script)
    return base58check_encode(version, payload)


def script_to_p2wsh_address(script: bytes, hrp: str = MAINNET_HRP) -> str:
    """
    Encode a witness script as P2WSH (SegWit v0) address (tc1q... with 32-byte program).

    Args:
        script: Witness script bytes (e.g. multisig script)
        hrp: Bech32 HRP (default mainnet "tc")

    Returns:
        Bech32 P2WSH address
    """
    if not script:
        raise ScriptError("Script cannot be empty")
    witness_program = sha256(script)
    if len(witness_program) != 32:
        raise ScriptError("Witness program must be 32 bytes")
    data_5bit = convert_bits(list(witness_program), 8, 5, True)
    data_with_version = [0] + data_5bit
    return bech32_encode(hrp, data_with_version)


def pubkey_to_p2pkh_address(pubkey: bytes, version: int = P2PKH_VERSION) -> str:
    """
    Convert public key to P2PKH address (T...).

    Args:
        pubkey: 33-byte compressed public key
        version: P2PKH version byte (default mainnet 0x41)

    Returns:
        Base58Check P2PKH address
    """
    if len(pubkey) != 33:
        raise ScriptError(f"Compressed pubkey must be 33 bytes, got {len(pubkey)}")
    payload = hash160(pubkey)
    return base58check_encode(version, payload)


def pubkey_to_p2sh_p2pkh_address(pubkey: bytes, version: int = P2SH_VERSION) -> str:
    """
    Build P2SH address that pays to P2PKH redeem script (single-sig P2SH, M...).

    Args:
        pubkey: 33-byte compressed public key
        version: P2SH version byte (default mainnet 0x32)

    Returns:
        Base58Check P2SH address
    """
    redeem = build_p2pkh_script(pubkey)
    return script_to_p2sh_address(redeem, version)


def build_p2wpkh_redeem_script(pubkey: bytes) -> bytes:
    """
    Build the witness-v0 "redeem script" used to nest a P2WPKH output
    inside P2SH, per BIP-49: OP_0 <20-byte-hash160(pubkey)>.

    Args:
        pubkey: 33-byte compressed public key

    Returns:
        22-byte redeem script (0x00 0x14 <20-byte-hash>)
    """
    if len(pubkey) != 33:
        raise ScriptError(f"Compressed pubkey must be 33 bytes, got {len(pubkey)}")
    h = hash160(pubkey)
    return bytes([OP_0, 0x14]) + h


def pubkey_to_p2sh_p2wpkh_address(pubkey: bytes, version: int = P2SH_VERSION) -> str:
    """
    Build a BIP-49 nested SegWit address: P2SH-wrapped P2WPKH (single-sig, M...).

    This is the standard BIP-49 "P2SH-P2WPKH" address, distinct from
    ``pubkey_to_p2sh_p2pkh_address`` (which wraps a legacy P2PKH script,
    not a witness program).

    Args:
        pubkey: 33-byte compressed public key
        version: P2SH version byte (default mainnet 0x32)

    Returns:
        Base58Check P2SH address
    """
    redeem = build_p2wpkh_redeem_script(pubkey)
    return script_to_p2sh_address(redeem, version)

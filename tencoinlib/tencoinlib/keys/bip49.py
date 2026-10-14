from typing import Tuple

from .bip32 import ExtendedPrivateKey, derive_path_from_seed
from .ec import privkey_to_pubkey
from ..constants import BIP49_PURPOSE, COIN_TYPE
from ..transaction.script import pubkey_to_p2sh_p2wpkh_address


class BIP49Error(Exception):
    """BIP-49 related errors"""
    pass


def bip49_account_path(account: int = 0) -> str:
    """
    Build the BIP-49 account-level path: m/49'/COIN_TYPE'/account'.

    This is the path an account xprv/xpub should be exported at for
    nested SegWit (P2SH-P2WPKH), kept separate from the BIP-84 path.
    """
    return f"m/{BIP49_PURPOSE}'/{COIN_TYPE}'/{account}'"


def bip49_address_path(account: int = 0, change: int = 0, index: int = 0) -> str:
    """Build the full BIP-49 address path: m/49'/COIN_TYPE'/account'/change/index."""
    return f"m/{BIP49_PURPOSE}'/{COIN_TYPE}'/{account}'/{change}/{index}"


def derive_bip49_address_from_seed(seed: bytes, account: int = 0,
                                    change: int = 0, index: int = 0) -> Tuple[bytes, str]:
    """
    Derive BIP-49 nested SegWit (P2SH-P2WPKH) address from seed.

    Uses its own purpose field (49'), independent from BIP-84 (84').

    Args:
        seed: 64-byte seed
        account: Account number (default: 0)
        change: 0 for external, 1 for change
        index: Address index

    Returns:
        (private_key, address)
    """
    # Build derivation path: m/49'/5353'/{account}'/{change}/{index}
    path = bip49_address_path(account, change, index)

    # Derive private key
    private_key, _ = derive_path_from_seed(seed, path)

    # Get compressed public key
    public_key = privkey_to_pubkey(private_key, compressed=True)

    # Create P2SH-wrapped SegWit (P2WPKH-in-P2SH) address
    address = public_key_to_p2sh_segwit(public_key)

    return private_key, address


def public_key_to_p2sh_segwit(public_key: bytes) -> str:
    """
    Convert public key to BIP-49 nested SegWit (P2SH-P2WPKH) address.

    Args:
        public_key: 33-byte compressed public key

    Returns:
        Base58Check P2SH address (M...)
    """
    if len(public_key) != 33:
        raise BIP49Error(f"Invalid public key length: {len(public_key)}")

    return pubkey_to_p2sh_p2wpkh_address(public_key)


def get_default_address_from_seed(seed: bytes) -> Tuple[bytes, str, str]:
    """
    Get default BIP-49 address (m/49'/5353'/0'/0/0).

    Args:
        seed: 64-byte seed

    Returns:
        (private_key, public_key, address)
    """
    private_key, address = derive_bip49_address_from_seed(
        seed, account=0, change=0, index=0
    )

    public_key = privkey_to_pubkey(private_key, compressed=True)

    return private_key, public_key.hex(), address


def get_account_xprv_from_seed(seed: bytes, account: int = 0) -> str:
    """
    Export the BIP-49 account-level extended private key
    (m/49'/COIN_TYPE'/account') as xprv.

    Args:
        seed: 64-byte seed
        account: Account number

    Returns:
        Base58Check xprv string
    """
    master = ExtendedPrivateKey.from_seed(seed)
    account_key = master.derive_path(bip49_account_path(account))
    return account_key.to_xprv()


def get_account_xpub_from_seed(seed: bytes, account: int = 0) -> str:
    """
    Export the BIP-49 account-level extended public key
    (m/49'/COIN_TYPE'/account') as xpub.

    Args:
        seed: 64-byte seed
        account: Account number

    Returns:
        Base58Check xpub string
    """
    master = ExtendedPrivateKey.from_seed(seed)
    account_key = master.derive_path(bip49_account_path(account))
    return account_key.to_public().to_xpub()

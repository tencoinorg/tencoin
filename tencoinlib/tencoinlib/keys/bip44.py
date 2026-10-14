from typing import Tuple

from .bip32 import ExtendedPrivateKey, derive_path_from_seed
from .ec import privkey_to_pubkey
from ..constants import BIP44_PURPOSE, COIN_TYPE
from ..transaction.script import pubkey_to_p2pkh_address


class BIP44Error(Exception):
    """BIP-44 related errors"""
    pass


def bip44_account_path(account: int = 0) -> str:
    """
    Build the BIP-44 account-level path: m/44'/COIN_TYPE'/account'.

    This is the path an account xprv/xpub should be exported at
    (e.g. via get_account_xprv / get_account_xpub for legacy P2PKH).
    """
    return f"m/{BIP44_PURPOSE}'/{COIN_TYPE}'/{account}'"


def bip44_address_path(account: int = 0, change: int = 0, index: int = 0) -> str:
    """Build the full BIP-44 address path: m/44'/COIN_TYPE'/account'/change/index."""
    return f"m/{BIP44_PURPOSE}'/{COIN_TYPE}'/{account}'/{change}/{index}"


def derive_bip44_address_from_seed(seed: bytes, account: int = 0,
                                    change: int = 0, index: int = 0) -> Tuple[bytes, str]:
    """
    Derive BIP-44 legacy P2PKH address from seed.

    Args:
        seed: 64-byte seed
        account: Account number (default: 0)
        change: 0 for external, 1 for change
        index: Address index

    Returns:
        (private_key, address)
    """
    # Build derivation path: m/44'/5353'/{account}'/{change}/{index}
    path = bip44_address_path(account, change, index)

    # Derive private key
    private_key, _ = derive_path_from_seed(seed, path)

    # Get compressed public key
    public_key = privkey_to_pubkey(private_key, compressed=True)

    # Create legacy P2PKH address
    address = public_key_to_p2pkh(public_key)

    return private_key, address


def public_key_to_p2pkh(public_key: bytes) -> str:
    """
    Convert public key to legacy P2PKH address.

    Args:
        public_key: 33-byte compressed public key

    Returns:
        Base58Check P2PKH address (T...)
    """
    if len(public_key) != 33:
        raise BIP44Error(f"Invalid public key length: {len(public_key)}")

    return pubkey_to_p2pkh_address(public_key)


def get_default_address_from_seed(seed: bytes) -> Tuple[bytes, str, str]:
    """
    Get default BIP-44 address (m/44'/5353'/0'/0/0).

    Args:
        seed: 64-byte seed

    Returns:
        (private_key, public_key, address)
    """
    private_key, address = derive_bip44_address_from_seed(
        seed, account=0, change=0, index=0
    )

    public_key = privkey_to_pubkey(private_key, compressed=True)

    return private_key, public_key.hex(), address


def get_account_xprv_from_seed(seed: bytes, account: int = 0) -> str:
    """
    Export the BIP-44 account-level extended private key
    (m/44'/COIN_TYPE'/account') as xprv.

    Args:
        seed: 64-byte seed
        account: Account number

    Returns:
        Base58Check xprv string
    """
    master = ExtendedPrivateKey.from_seed(seed)
    account_key = master.derive_path(bip44_account_path(account))
    return account_key.to_xprv()


def get_account_xpub_from_seed(seed: bytes, account: int = 0) -> str:
    """
    Export the BIP-44 account-level extended public key
    (m/44'/COIN_TYPE'/account') as xpub.

    Args:
        seed: 64-byte seed
        account: Account number

    Returns:
        Base58Check xpub string
    """
    master = ExtendedPrivateKey.from_seed(seed)
    account_key = master.derive_path(bip44_account_path(account))
    return account_key.to_public().to_xpub()

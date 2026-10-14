# tencoinlib/__init__.py
"""
tencoinlib - Official Python library for Tencoin
"""

from .constants import (
    MAINNET_HRP,
    TENOS_PER_TEC,
    DUST_LIMIT,
    DEFAULT_RPC_PORT,
    COIN_TYPE,
    DERIVATION_PATH,
    DEFAULT_RPC_TOKEN,
    DEVELOPER_ADDRESS,
    # Conditional output constants
    COND_FLAG_TIMELOCK,
    COND_FLAG_HASHLOCK,
    TIMELOCK_MODE_HEIGHT,
    TIMELOCK_MODE_TIMESTAMP,
    HASHLOCK_MIN_PREIMAGE,
    HASHLOCK_MAX_PREIMAGE,
    HASHLOCK_HASH_SIZE,
)

from .wallet import Wallet, WalletError
from .rpc import (
    RPCClient, RPCError, PublicKeyInfo, PublicKeyNotFoundError, PublicKeyVerificationError,
)
from . import tmsg
from .tmsg import (
    TMSGError, TMSGKeyError, TMSGFormatError, TMSGDecryptionError, TMSGSizeError,
    TMSGTransaction, build_tmsg_transaction,
)
from .transaction import (
    Transaction, TxIn, TxOut, TimelockTxOut, HashlockTxOut, parse_transaction,
    TransactionBuilder, TransactionBuilderError,
    SegWitSigner, LegacySigner, TransactionSigner, SigningError,
    HashlockError,
    InvalidHashlockSecretError,
    InvalidHashlockUTXOError,
    HashlockSpendBuildError,
    HashlockSpendSigningError,
    HashlockSpendResult,
    prepare_hashlock_secret,
    verify_hashlock_secret,
    build_hashlock_spend,
    sign_hashlock_input,
    finalize_hashlock_spend,
    spend_hashlock,
    FeeCalculator,
    decode_address, address_to_script, is_valid_address,
    get_address_type, AddressError,
)

from .message import (
    sign_message,
    verify_message,
    recover_address_from_signature,
    MessageSigningError,
)

from .integrity import compute_library_hash, get_file_manifest

from .secret import (
    generate_secret,
    parse_secret,
    validate_secret,
    check_secret,
    is_valid_tencoin_secret,
    secret_to_preimage,
    hash_preimage,
    soft_warnings,
    SecretError,
    SecretFormatError,
)

# Version
__version__ = "0.4.0"

__all__ = [
    # Constants
    "MAINNET_HRP",
    "TENOS_PER_TEC",
    "DUST_LIMIT",
    "DEFAULT_RPC_PORT",
    "DEFAULT_RPC_TOKEN",
    "COIN_TYPE",
    "DERIVATION_PATH",

    # Conditional output constants
    "COND_FLAG_TIMELOCK",
    "COND_FLAG_HASHLOCK",
    "TIMELOCK_MODE_HEIGHT",
    "TIMELOCK_MODE_TIMESTAMP",
    "HASHLOCK_MIN_PREIMAGE",
    "HASHLOCK_MAX_PREIMAGE",
    "HASHLOCK_HASH_SIZE",

    # Wallet
    "Wallet",
    "WalletError",

    # RPC
    "RPCClient",
    "PublicKeyInfo",
    "PublicKeyNotFoundError",
    "PublicKeyVerificationError",
    "tmsg",
    "TMSGError",
    "TMSGKeyError",
    "TMSGFormatError",
    "TMSGDecryptionError",
    "TMSGSizeError",
    "TMSGTransaction",
    "build_tmsg_transaction",
    "RPCError",

    # Transaction
    "Transaction",
    "TxIn",
    "TxOut",
    "TimelockTxOut",
    "HashlockTxOut",
    "parse_transaction",
    "TransactionBuilder",
    "TransactionBuilderError",
    "SegWitSigner",
    "LegacySigner",
    "TransactionSigner",
    "SigningError",
    "HashlockError",
    "InvalidHashlockSecretError",
    "InvalidHashlockUTXOError",
    "HashlockSpendBuildError",
    "HashlockSpendSigningError",
    "HashlockSpendResult",
    "prepare_hashlock_secret",
    "verify_hashlock_secret",
    "build_hashlock_spend",
    "sign_hashlock_input",
    "finalize_hashlock_spend",
    "spend_hashlock",
    "FeeCalculator",
    "decode_address",
    "address_to_script",
    "is_valid_address",
    "get_address_type",
    "AddressError",

    # Message Signing
    "sign_message",
    "verify_message",
    "recover_address_from_signature",
    "MessageSigningError",

    # TCS Secret generator
    "generate_secret",
    "parse_secret",
    "validate_secret",
    "check_secret",
    "is_valid_tencoin_secret",
    "secret_to_preimage",
    "hash_preimage",
    "soft_warnings",
    "SecretError",
    "SecretFormatError",

    # Version
    "__version__",
]
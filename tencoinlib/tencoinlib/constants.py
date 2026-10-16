# tencoinlib/constants.py


MAINNET_HRP = "tc"


COIN_TYPE = 5353


# BIP purposes
BIP44_PURPOSE = 44  # Legacy P2PKH
BIP49_PURPOSE = 49  # Nested SegWit (P2SH-P2WPKH)
BIP84_PURPOSE = 84  # Native SegWit (P2WPKH)


# Default BIP44 derivation path for the primary P2PKH address
DERIVATION_PATH = f"m/{BIP44_PURPOSE}'/{COIN_TYPE}'/0'/0/0"


BIP39_ENTROPY_BITS = 128  
BIP39_CHECKSUM_BITS = 4   


P2PKH_VERSION = 0x41      
P2SH_VERSION = 0x32       
P2WPKH_VERSION = 0        


TENOS_PER_TEC = 100_000_000
DUST_LIMIT = 546


DEFAULT_RPC_PORT = 10111
DEFAULT_P2P_PORT = 10110


DEFAULT_RPC_TOKEN = ""


DEFAULT_SEED_NODES = [
    "seed.tencoin.org",
]


DEFAULT_FEE_RATE = 10  
PRIORITY_FEE_RATE = 20
ECONOMY_FEE_RATE = 5
MIN_RELAY_FEE = 1000  


MAINNET_MAGIC = b'\x0a\x0d\x0e\x10'
TESTNET_MAGIC = b'\x0b\x11\x09\x07'


OP_DUP = 0x76
OP_HASH160 = 0xa9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xac
OP_EQUAL = 0x87
OP_RETURN = 0x6a
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d


DEVELOPER_ADDRESS = "TASH999uKBUFN1AqAkDjJ8dQqWbXw6G5bh"

COND_FLAG_TIMELOCK = 0xC1
COND_FLAG_HASHLOCK = 0xC2

TIMELOCK_MODE_RESERVED = 0x00
TIMELOCK_MODE_HEIGHT = 0x01
TIMELOCK_MODE_TIMESTAMP = 0x02

# C2 HASHLOCK preimage size limits — consensus rules, not just convention.
# Preimage must be raw bytes (text → UTF-8 → bytes before passing here).
HASHLOCK_MIN_PREIMAGE = 1   # bytes
HASHLOCK_MAX_PREIMAGE = 64  # bytes
HASHLOCK_HASH_SIZE = 32     # bytes — SHA256(preimage), single round

# ── TCS secret generator ────────────────────────────────────────────────
# Must stay identical to the node (tencoin/wallet/secret_engine.py):
#   TCS- + 55 random characters (A-Z, 0-9) + 5 checksum characters = 64 characters,
#   checksum = SHA-256("TCS-" + random part) as upper-case hex, first 5 characters.
SECRET_PREFIX = "TCS-"
SECRET_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SECRET_TOTAL_LENGTH = 64                  # the prefix IS counted
SECRET_CHECKSUM_LENGTH = 5
SECRET_BODY_LENGTH = SECRET_TOTAL_LENGTH - len(SECRET_PREFIX) - SECRET_CHECKSUM_LENGTH   # 55 random characters


# ── OP_RETURN / TMSG (Tencoin Message) ──────────────────────────────────
# The node accepts up to 1024 data bytes in an OP_RETURN output.
OP_RETURN_MAX_DATA = 1024

# A script whose length is a single-byte varint in 0xC1..0xCF is indistinguishable
# from a conditional-output flag byte when the output is parsed (see core.py), so
# OP_RETURN scripts of 193..207 bytes must never be produced.
OUTPUT_FLAG_RANGE = range(0xC1, 0xD0)

TMSG_MAGIC = b"TMSG"
TMSG_VERSION_1 = 0x01                   # exactly one recipient public key
TMSG_VERSION_2 = 0x02                   # 2..255 recipient public keys, 1-of-N decryption
TMSG_MAX_RECIPIENTS = 255               # N is a single byte
TMSG_RECOMMENDED_MAX_RECIPIENTS = 20
TMSG_GCM_TAG_SIZE = 16
TMSG_NONCE_SIZE = 12
TMSG_RECIPIENT_BLOCK_SIZE = 33 + 12 + 48   # ephemeral pub + wrap nonce + wrapped key (32 + 16 tag)

# Minimum payment (Tenos) of the first output of an on-chain TMSG transaction.
# The dust limit does NOT apply to transactions that carry a TMSG.
TMSG_MIN_PAYMENT = 1

# secp256k1 field prime (used for public-key validation)
SECP256K1_FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


# ── WIF (Wallet Import Format) ──────────────────────────────────────────
# ASSUMED, not read from the node: P2PKH_VERSION + 0x80, the convention of the
# Bitcoin family (Bitcoin 0x00 -> 0x80, Litecoin 0x30 -> 0xB0, Dogecoin 0x1E -> 0x9E).
# Confirm it against a WIF exported by the node / wallet. Every WIF function takes
# version= to override it, and version=None accepts any version when decoding.
WIF_VERSION = 0xC1

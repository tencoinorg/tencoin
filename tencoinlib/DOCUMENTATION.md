# Tencoinlib Documentation

Complete and comprehensive documentation for the Tencoinlib Python library.

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Wallet](#wallet)
5. [Wallet Storage](#wallet-storage)
6. [Transactions](#transactions)
7. [RPC Client](#rpc-client)
8. [Address Utilities](#address-utilities)
9. [Fee Management](#fee-management) — includes `set_fee()` and Timelock Outputs
10. [Key Management](#key-management)
11. [Transaction Signing](#transaction-signing)
12. [Multisig Transactions](#multisig-transactions)
13. [Message Signing](#message-signing)
14. [HASHLOCK (C2) Outputs](#hashlock-c2-outputs) — TCS secrets, creating and spending
15. [TMSG (Tencoin Message)](#tmsg-tencoin-message) — encrypted messages, files and folders, off-chain and on-chain
16. [Complete Examples](#complete-examples)
17. [API Reference](#api-reference)
18. [Error Handling](#error-handling)
19. [Constants and Configuration](#constants-and-configuration)
20. [Best Practices](#best-practices)

---

## Introduction

**Tencoinlib** is the official Python library for working with the Tencoin cryptocurrency. It provides a comprehensive set of tools for creating HD wallets, building and signing transactions, and interacting with Tencoin nodes via RPC.

### Key Features

- ✅ **HD Wallets**: Full support for BIP-39 (mnemonic phrases) + BIP-84 (SegWit addresses)
- ✅ **BIP-32 Extended Keys**: Master/account-level xprv/xpub with standard serialization
- ✅ **Watch-Only Wallets**: Create wallets from xpub only (no seed/private keys)
- ✅ **Raw Key Import**: Create a wallet from a single raw private key (no mnemonic, no chain code)
- ✅ **Multiple Address Types**: 
  - **SegWit v0** (P2WPKH): Native SegWit addresses (`tc1q...`), BIP-84
  - **Legacy P2PKH**: Pay-to-pubkey-hash addresses (`T...`), BIP-44
  - **Nested SegWit P2SH** (P2SH-P2WPKH): Pay-to-script-hash-wrapped SegWit addresses (`M...`), BIP-49
  - **P2WSH**: SegWit script addresses (`tc1q...` with 32-byte program)
- ✅ **Independent BIP-44 / BIP-49 / BIP-84 Purpose Fields**: Legacy, nested-SegWit, and native-SegWit addresses each derive under their own purpose (44'/49'/84'), with dedicated account-level xprv/xpub for each
- ✅ **Custom Scripts**: Support for multisig and custom redeem/witness scripts
- ✅ **Transaction Signing**: Automatic detection and signing for SegWit (BIP-143), Legacy (P2PKH/P2SH), and Multisig (P2SH/P2WSH, any m-of-n up to 15-of-15) inputs
- ✅ **Message Signing**: Bitcoin Core–compatible message signing and verification with public key recovery
- ✅ **HASHLOCK (C2) Outputs**: Create hash-locked outputs and spend them (owner signature + secret preimage) — in one call with `wallet.spend_hashlock()` or step by step
- ✅ **TMSG (Tencoin Message)**: Encrypt messages, files and folders to one public key (v1) or many (v2, any one private key decrypts) — off-chain, or on-chain in an `OP_RETURN` output (up to 958 bytes of message)
- ✅ **getpublickey**: Find the public key of an address on-chain (`rpc.get_public_key()`), verified locally against the address
- ✅ **TCS Secrets**: Generate and validate `TCS-...` secrets (64 characters including a checksum) in exactly the format used by Tencoin Core
- ✅ **Key Derivation**: Standard BIP-84 derivation path `m/84'/5353'/0'/0/0`, BIP-44 path `m/44'/5353'/0'/0/0`, BIP-49 path `m/49'/5353'/0'/0/0`, and generic BIP-32 paths
- ✅ **Mnemonic Phrases**: 12, 15, 18, 21, or 24 word English mnemonics
- ✅ **Wallet Recovery**: Restore wallets from mnemonic phrases
- ✅ **Encrypted Wallet Storage**: TCW v1 binary format with AES-256-GCM encryption and Argon2id key derivation
- ✅ **Locked/Unlocked State Machine**: Secret material only in RAM when needed; explicit lock/unlock lifecycle
- ✅ **Transaction Building**: Create and sign transactions with all address types
- ✅ **RPC Client**: Connect to Tencoin nodes via JSON-RPC
- ✅ **Fee Calculation**: Automatic fee estimation and management
- ✅ **Address Validation**: Support for multiple address types

### Supported Standards

- **BIP-39**: Mnemonic code for generating deterministic keys
- **BIP-32**: Hierarchical Deterministic Wallets
- **BIP-44**: Derivation scheme for legacy P2PKH addresses
- **BIP-49**: Derivation scheme for nested SegWit (P2SH-P2WPKH) addresses
- **BIP-84**: Derivation scheme for P2WPKH (SegWit v0)
- **BIP-143**: Transaction signature verification for SegWit
- **BIP-13**: Pay-to-script-hash (P2SH)
- **BIP-141**: SegWit (P2WSH support)

---

## Installation

### Install from PyPI

```bash
pip install tencoinlib
```

### Install with Optional Dependencies

```bash
# For development tools (pytest, black, ruff)
pip install tencoinlib[dev]

# For async support (when available)
pip install tencoinlib[async]

# For enhanced mnemonic support
pip install tencoinlib[mnemonic]
```

### Requirements

- Python >= 3.8
- `ecdsa>=0.18.0` - For transaction signing
- `requests>=2.28.0` - For RPC client
- `bech32>=1.2.0` - For SegWit address encoding
- `coincurve>=13.0.0` - For message signing and public key recovery
- `cryptography>=41.0.0` - For AES-256-GCM wallet encryption
- `argon2-cffi>=21.3.0` - For Argon2id key derivation (`.tcw` files)

---

## Quick Start

### Create a New Wallet

```python
from tencoinlib import Wallet

# Create a new wallet with 12-word mnemonic (returned UNLOCKED)
wallet = Wallet.create()

print(f"Mnemonic: {wallet.get_mnemonic()}")
print(f"Address:  {wallet.get_address()}")

# Save to an encrypted .tcw file
wallet.save("my_wallet.tcw", password="my-strong-password")
```

### Recover a Wallet

```python
from tencoinlib import Wallet

# Recover wallet from mnemonic
mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident"
wallet = Wallet.recover(mnemonic)

print(f"Recovered Address: {wallet.get_address()}")
```

### Send a Transaction

```python
from tencoinlib import Wallet, TransactionBuilder, TransactionSigner
from tencoinlib.rpc import RPCClient
from tencoinlib.transaction.address import address_to_script

# Load and unlock wallet from encrypted file
wallet = Wallet.load("my_wallet.tcw").unlock("my-strong-password")
rpc = RPCClient(host="127.0.0.1", port=10111, token="your-token")

# Get UTXOs
utxos = rpc.list_unspent(wallet.get_address())

# Build transaction
builder = TransactionBuilder()
for utxo in utxos:
    builder.add_input(
        txid=utxo["txid"],
        vout=utxo["vout"],
        value=utxo["amount"],
        script_pubkey=bytes.fromhex(utxo["scriptPubKey"])
    )
# Recipient can be SegWit (tc1q...), P2PKH (T...), or P2SH (M...)
builder.add_output("tc1q...", 1000000)
builder.set_change_address(wallet.get_address())

tx, fee = builder.build()

# Sign transaction (automatically detects address type)
utxo_data = [{
    "value": u["amount"],
    "script_pubkey": bytes.fromhex(u["scriptPubKey"]),
    "address": wallet.get_address()  # Can be any address type
} for u in utxos]
private_keys = [bytes.fromhex(wallet.get_private_key_hex())] * len(utxos)

# TransactionSigner automatically handles SegWit, P2PKH, and P2SH
signed_tx = TransactionSigner.sign_transaction(tx, utxo_data, private_keys)

# Broadcast
txid = rpc.send_raw_transaction(signed_tx.serialize().hex())
print(f"Transaction sent! TXID: {txid}")
```

---

## Wallet

The `Wallet` class provides high-level HD wallet functionality for Tencoin.

### Creating Wallets

#### Create New Wallet

```python
from tencoinlib import Wallet

# Create wallet with default 12-word mnemonic (128-bit entropy)
wallet = Wallet.create()

# Create wallet with different strengths
wallet_15 = Wallet.create(strength=160)   # 15 words
wallet_18 = Wallet.create(strength=192)   # 18 words
wallet_21 = Wallet.create(strength=224)   # 21 words
wallet_24 = Wallet.create(strength=256)   # 24 words

# Valid strength values: 128, 160, 192, 224, 256
```

#### Recover from Mnemonic

```python
from tencoinlib import Wallet

# Recover without passphrase
mnemonic = "word1 word2 word3 ... word12"
wallet = Wallet.recover(mnemonic)

# Recover with BIP-39 passphrase
wallet = Wallet.recover(mnemonic, passphrase="my-secret-passphrase")
```

**Note**: The mnemonic phrase must be valid BIP-39 format with correct checksum.

### Accessing Wallet Information

```python
# Get SegWit address (P2WPKH) — default
address = wallet.get_address()
print(f"Address: {address}")  # e.g., "tc1q..."

# Note: P2PKH/P2SH/P2WPKH are derived under independent purpose fields
# (BIP-44/49/84) — NOT the same key. See the note under Address Types.
print("SegWit:  ", wallet.get_address())              # tc1q...
print("P2PKH:   ", wallet.get_address("p2pkh"))       # T...
print("P2SH:    ", wallet.get_address("p2sh"))        # M... (single-sig P2SH)

# Get private key (hex format)
private_key = wallet.get_private_key_hex()
print(f"Private Key: {private_key}")

# Get public key (hex format, compressed)
public_key = wallet.get_public_key_hex()
print(f"Public Key: {public_key}")

# Get mnemonic phrase (only if wallet was created or recovered with mnemonic)
try:
    mnemonic = wallet.get_mnemonic()
    print(f"Mnemonic: {mnemonic}")
except WalletError:
    print("Mnemonic not available")
```

### Address Types and Custom Scripts

The `get_address()` method supports multiple address types and custom scripts (multisig, custom redeem scripts).

#### Standard Address Types

```python
wallet = Wallet.create()

# SegWit v0 native (P2WPKH) - default, BIP-84 (m/84'/5353'/0'/0/0)
segwit_addr = wallet.get_address()  # or wallet.get_address("p2wpkh")
print(f"SegWit: {segwit_addr}")  # tc1q...

# Legacy P2PKH - BIP-44 (m/44'/5353'/0'/0/0)
p2pkh_addr = wallet.get_address("p2pkh")
print(f"P2PKH: {p2pkh_addr}")  # T...

# Single-sig nested SegWit (P2SH-wrapped P2WPKH) - BIP-49 (m/49'/5353'/0'/0/0)
p2sh_addr = wallet.get_address("p2sh")
print(f"P2SH: {p2sh_addr}")  # M...
```

> **Note — independent purpose fields.** `p2pkh`, `p2sh`, and `p2wpkh` are
> each derived under their own BIP-32 purpose (44', 49', and 84'
> respectively), from three completely separate branches of the tree.
> `get_address("p2sh")` returns the standard **BIP-49** nested-SegWit
> address (a P2WPKH witness program wrapped in P2SH), *not* a P2SH-wrapped
> P2PKH script — the two look similar but are different scripts spent in
> different ways. If you specifically need a P2SH address that wraps a
> plain P2PKH script instead, build it explicitly with
> `pubkey_to_p2sh_p2pkh_address()` (see
> [Script Building Functions](#script-building-functions)).

#### Custom Scripts (P2SH and P2WSH)

You can create addresses from custom redeem/witness scripts (e.g., multisig, custom logic).

##### P2SH with Custom Redeem Script

```python
from tencoinlib.transaction import build_multisig_script, script_to_p2sh_address

# Build 2-of-3 multisig redeem script
pubkeys = [
    bytes.fromhex("02a1b2c3..."),  # Public key 1 (33 bytes)
    bytes.fromhex("03d4e5f6..."),  # Public key 2
    bytes.fromhex("0298a7b8..."),  # Public key 3
]

# Create multisig script (sorted for canonical form)
redeem_script = build_multisig_script(2, pubkeys, sort_pubkeys=True)

# Get P2SH address from redeem script
p2sh_multisig_addr = script_to_p2sh_address(redeem_script)
print(f"2-of-3 P2SH: {p2sh_multisig_addr}")  # M...

# Or use wallet.get_address() with script
p2sh_addr = wallet.get_address("p2sh", script=redeem_script)
```

##### P2WSH (SegWit Script) with Custom Witness Script

```python
from tencoinlib.transaction import build_multisig_script, script_to_p2wsh_address

# Build 2-of-3 multisig witness script
pubkeys = [
    bytes.fromhex("02a1b2c3..."),
    bytes.fromhex("03d4e5f6..."),
    bytes.fromhex("0298a7b8..."),
]

witness_script = build_multisig_script(2, pubkeys, sort_pubkeys=True)

# Get P2WSH address (SegWit v0 script)
p2wsh_addr = script_to_p2wsh_address(witness_script)
print(f"2-of-3 P2WSH: {p2wsh_addr}")  # tc1q...

# Or use wallet.get_address() with script
p2wsh_addr = wallet.get_address("p2wsh", script=witness_script)
```

##### Complete Example: 2-of-3 P2WSH Multisig Wallet

```python
from tencoinlib import Wallet
from tencoinlib.transaction import build_multisig_script
from tencoinlib.keys.bip32 import derive_path_from_seed
from tencoinlib.keys.ec import privkey_to_pubkey

# Generate master mnemonic
wallet = Wallet.create()
mnemonic = wallet.get_mnemonic()
seed = wallet.seed  # Access seed for derivation

# Derive three keys from different paths
paths = [
    "m/84'/5353'/0'/0/0",
    "m/84'/5353'/0'/0/1",
    "m/84'/5353'/0'/0/2"
]

pubkeys = []
for path in paths:
    priv, _ = derive_path_from_seed(seed, path)
    pub = privkey_to_pubkey(priv, compressed=True)
    pubkeys.append(pub)

# Build 2-of-3 multisig witness script
witness_script = build_multisig_script(2, pubkeys, sort_pubkeys=True)

# Get P2WSH address
multisig_address = wallet.get_address("p2wsh", script=witness_script)
print(f"2-of-3 P2WSH Address: {multisig_address}")
print(f"Witness Script: {witness_script.hex()}")
```

#### Using Wallet.build_multisig_script()

For convenience, you can use the static method on `Wallet`:

```python
# Build multisig script (pubkeys can be bytes or hex strings)
pubkeys_hex = ["02a1b2c3...", "03d4e5f6...", "0298a7b8..."]
script = Wallet.build_multisig_script(2, pubkeys_hex)

# Use with get_address
addr = wallet.get_address("p2wsh", script=script)
```

### Deriving Additional Addresses

#### Derive Specific Address

```python
# Derive address at specific path: m/84'/5353'/{account}'/{change}/{index}
private_key_hex, address = wallet.derive_address(
    account=0,   # Account number (typically 0)
    change=0,    # 0 for external (receiving), 1 for change
    index=1      # Address index
)

print(f"Address: {address}")
print(f"Private Key: {private_key_hex}")
```

#### Get Next Address

```python
# Get next external address (automatically increments index)
priv_key, next_address = wallet.get_next_address(change=0)
print(f"Next receiving address: {next_address}")

# Get next change address
priv_key, change_address = wallet.get_next_address(change=1)
print(f"Next change address: {change_address}")
```

#### Derive Multiple Addresses

```python
# Derive first 5 receiving addresses
print("Receiving Addresses:")
for i in range(5):
    priv, addr = wallet.derive_address(account=0, change=0, index=i)
    print(f"  {i}: {addr}")

# Derive first 3 change addresses
print("\nChange Addresses:")
for i in range(3):
    priv, addr = wallet.derive_address(account=0, change=1, index=i)
    print(f"  {i}: {addr}")
```

### Account-Level Keys: BIP-44 / BIP-49 / BIP-84

Each address type has its own, fully independent purpose field and
therefore its own account-level xprv/xpub path:

| Address type              | Standard | Account path                 |
|---------------------------|----------|-------------------------------|
| P2PKH (legacy)             | BIP-44   | `m/44'/5353'/account'`         |
| P2SH-P2WPKH (nested SegWit)| BIP-49   | `m/49'/5353'/account'`         |
| P2WPKH (native SegWit)     | BIP-84   | `m/84'/5353'/account'`         |

`get_account_xprv()`/`get_account_xpub()` default to the BIP-84 path for
backward compatibility, but accept an explicit `purpose` argument to
reach the BIP-44 or BIP-49 branch instead. Dedicated convenience methods
are also available so call sites don't need to remember the purpose
numbers:

```python
wallet = Wallet.create()

# Explicit purpose argument
xpub_p2pkh  = wallet.get_account_xpub(0, purpose=44)   # m/44'/5353'/0'
xpub_p2sh   = wallet.get_account_xpub(0, purpose=49)   # m/49'/5353'/0'
xpub_p2wpkh = wallet.get_account_xpub(0)                # m/84'/5353'/0' (default)

# Named convenience methods (equivalent to the calls above)
xpub_p2pkh = wallet.get_account_xpub_p2pkh(0)
xprv_p2pkh = wallet.get_account_xprv_p2pkh(0)

xpub_p2sh_segwit = wallet.get_account_xpub_p2sh_segwit(0)
xprv_p2sh_segwit = wallet.get_account_xprv_p2sh_segwit(0)
```

The same separation is available at the module level for deriving
addresses directly from a seed, without a `Wallet` instance:

```python
from tencoinlib.keys.bip44 import derive_bip44_address_from_seed, get_account_xpub_from_seed
from tencoinlib.keys.bip49 import derive_bip49_address_from_seed
from tencoinlib.keys.bip84 import derive_bip84_address_from_seed

seed = b"..."  # 64-byte seed

_, p2pkh_addr  = derive_bip44_address_from_seed(seed, account=0, change=0, index=0)
_, p2sh_addr   = derive_bip49_address_from_seed(seed, account=0, change=0, index=0)
_, p2wpkh_addr = derive_bip84_address_from_seed(seed, account=0, change=0, index=0)

account_xpub = get_account_xpub_from_seed(seed, account=0)  # BIP-44 account xpub
```

See [Key Management](#key-management) for the full BIP-44/BIP-49/BIP-84
module reference.

### Importing a Raw Private Key

`Wallet.from_private_key()` builds a wallet from a single 32-byte
private key — no mnemonic, no seed, and **no BIP-32 chain code**. This
is fundamentally different from `Wallet.from_xprv()`: an xprv carries a
chain code and can derive an entire tree of child keys, while a bare
private key cannot derive anything beyond itself.

```python
from tencoinlib import Wallet

private_key = bytes.fromhex("...")  # 32 raw bytes
wallet = Wallet.from_private_key(private_key)

print(wallet.wallet_type)          # "privkey"
print(wallet.get_address("p2pkh")) # T... (canonical address for this type)
```

Because there is no chain code, operations that need one raise
`WalletError` on a `"privkey"` wallet:

```python
from tencoinlib import WalletError

try:
    wallet.get_address("p2wpkh")   # no other address types can be derived
except WalletError as e:
    print(e)

try:
    wallet.get_master_xpub()       # no HD tree to export
except WalletError as e:
    print(e)
```

This wallet type also exists to support importing a single key from an
external device — see the note at the end of
[Wallet Storage](#wallet-storage) below.

### Wallet Storage

Wallets are saved as **TCW v1** (TenCoin Wallet) encrypted binary files. Every `.tcw` file on disk is always encrypted — there is no plaintext save option.

#### TCW v1 Format

The `.tcw` file uses a binary container with the following structure:

```
┌──────────────────────────────┐
│ Magic + Version   4 bytes    │  b"TCW" + 0x01
│ KDF / Cipher IDs  2 bytes    │  Argon2id / AES-256-GCM
│ Flags, lengths    6 bytes    │
│ Payload length    8 bytes    │
├──────────────────────────────┤
│ Salt             32 bytes    │  random, stored in file
│ KDF parameters    4 bytes    │  time/memory/parallelism
│ Nonce            12 bytes    │  random, unique per save
├──────────────────────────────┤
│ Encrypted payload            │  AES-256-GCM ciphertext
│ + GCM tag        16 bytes    │  authentication tag
└──────────────────────────────┘
```

The fixed header is used as **AAD** (Additional Authenticated Data), meaning any tampering with the header — including version, algorithm IDs, or length fields — causes decryption to fail.

#### Save Wallet

The wallet must be **unlocked** to save (secrets need to be in RAM).

```python
# Create a new wallet (returned UNLOCKED)
wallet = Wallet.create()

# Save to encrypted .tcw file
wallet.save("my_wallet.tcw", password="my-strong-password")

# save_to_file() is an alias
wallet.save_to_file("my_wallet.tcw", password="my-strong-password")
```

#### Load Wallet (Locked)

`Wallet.load()` reads only the file header — no decryption, no secrets in RAM.

```python
# Load header only — wallet is LOCKED
wallet = Wallet.load("my_wallet.tcw")

print(wallet.is_locked)   # True
print(wallet.address)     # available (empty until unlocked)
```

#### Unlock Wallet

```python
wallet = Wallet.load("my_wallet.tcw")
wallet.unlock("my-strong-password")

print(wallet.is_locked)              # False
print(wallet.get_mnemonic())         # available
print(wallet.get_private_key_hex())  # available
```

#### Load and Unlock (one-liner)

```python
# Equivalent to Wallet.load(path).unlock(password)
wallet = Wallet.load_from_file("my_wallet.tcw", password="my-strong-password")
```

#### Lock Wallet

Call `lock()` to discard all secret material from RAM. Public metadata (address, indices) is preserved.

```python
wallet.unlock("my-strong-password")
# ... do work ...
wallet.lock()

print(wallet.is_locked)   # True
# wallet.get_mnemonic()   → raises WalletLockedError
```

#### Context Manager (Auto-lock)

The `unlocked()` context manager unlocks the wallet, yields it, then automatically locks on exit — even if an exception occurs.

```python
with wallet.unlocked("my-strong-password") as w:
    signed_tx = w.sign_transaction(tx)
    mnemonic  = w.get_mnemonic()

# wallet is locked again here
print(wallet.is_locked)   # True
```

#### Checking Wallet State

```python
print(wallet.is_locked)    # True / False
print(wallet.wallet_type)  # "hd" | "xpub" | "xprv" | "privkey"
print(wallet.is_watch_only)
```

#### Wrong Password

```python
from tencoinlib import WalletAuthError

try:
    wallet.unlock("wrong-password")
except WalletAuthError:
    print("Wrong password or corrupted file")
```

---

#### Exporting to / Importing from an External Device

For advanced use cases, wallet secrets can also be moved to or from a small
external companion device (an ESP-based hardware wallet), which uses its
own lightweight encrypted container instead of the full `.tcw` format:

```python
# Export this wallet's secrets for the external device
blob = wallet.export_to_esp_blob(esp_password="device-password")

# Import secrets that came from the external device
wallet = Wallet.import_from_esp_blob(blob, esp_password="device-password")
```

The password on each side may differ, and the key derivation used for the
device format is intentionally lighter-weight to suit constrained hardware —
use a strong, unique password when exporting to it. See `tencoinlib.wallet_storage`
for the underlying `esp_blob_to_tcw_file` / `tcw_file_to_esp_blob` helpers.

---

## Transactions

The transaction system allows you to create, build, and sign Tencoin transactions.

### TransactionBuilder

`TransactionBuilder` is the main class for constructing transactions.

#### Basic Transaction Building

```python
from tencoinlib import TransactionBuilder

# Initialize builder
builder = TransactionBuilder()

# Add input (UTXO)
builder.add_input(
    txid="abc123...",           # Previous transaction ID (hex, big-endian)
    vout=0,                     # Output index in previous transaction
    value=1000000,              # Amount in Tenos
    script_pubkey=b"..."        # ScriptPubKey of the UTXO
)

# Add output (recipient)
builder.add_output(
    address="tc1q...",          # Recipient address
    amount=500000               # Amount to send in Tenos
)

# Set change address
builder.set_change_address("tc1q...")

# Build transaction
transaction, fee = builder.build()
print(f"Fee: {fee} Tenos")
```

#### Advanced Transaction Configuration

```python
builder = TransactionBuilder()

# Set custom fee rate (Tenos per byte)
builder.set_fee_rate(50)  # Higher fee = faster confirmation

# Enable/disable SegWit (default: True)
builder.set_segwit(True)

# Set transaction locktime
builder.set_locktime(0)  # 0 = immediate

# Set transaction version
builder.set_version(1)  # Default is 1

# Build transaction
tx, fee = builder.build()
```

#### Multiple Inputs and Outputs

```python
builder = TransactionBuilder()

# Add multiple inputs
for utxo in utxos:
    builder.add_input(
        txid=utxo["txid"],
        vout=utxo["vout"],
        value=utxo["amount"],
        script_pubkey=bytes.fromhex(utxo["scriptPubKey"]),
        sequence=0xffffffff
    )

# Add multiple outputs
builder.add_output("tc1q...", 1000000)  # Payment 1 (tc1q... / T... / M...)
builder.add_output("tc1q...", 500000)   # Payment 2 (tc1q... / T... / M...)
builder.add_output("tc1q...", 200000)   # Payment 3 (tc1q... / T... / M...)

# Set change address
builder.set_change_address("tc1q...")

tx, fee = builder.build()
```

#### Transaction Summary

```python
# Get transaction summary before building
summary = builder.get_summary()
print(f"Inputs: {summary['inputs_count']}")
print(f"Outputs: {summary['outputs_count']}")
print(f"Total Input: {summary['total_input']} Tenos")
print(f"Total Output: {summary['total_output']} Tenos")
print(f"Estimated Fee: {summary['fee']} Tenos")
print(f"Change Amount: {summary['change_amount']} Tenos")
print(f"Has Change: {summary['has_change']}")
```

#### Helper Methods

```python
# Calculate total input amount
total_input = builder.calculate_total_input()

# Calculate total output amount
total_output = builder.calculate_total_output()

# Calculate estimated fee
estimated_fee = builder.calculate_fee()

# Calculate change amount
change_amount, has_change = builder.calculate_change()

# Build raw hex directly
raw_hex, fee = builder.build_raw()
```

#### Transaction Builder Methods

```python
# Clear all inputs and outputs
builder.clear()

# Create a copy of the builder
builder_copy = builder.copy()
```

### Transaction Object

The `Transaction` class represents a Tencoin transaction.

#### Transaction Properties

```python
from tencoinlib.transaction import Transaction, TxIn, TxOut

# Create transaction manually
tx = Transaction(
    version=1,
    vin=[TxIn(prev_txid="...", vout=0)],
    vout=[TxOut(value=1000000, script_pubkey=b"...")],
    locktime=0
)

# Access properties
print(f"Version: {tx.version}")
print(f"Inputs: {len(tx.vin)}")
print(f"Outputs: {len(tx.vout)}")
print(f"Locktime: {tx.locktime}")
print(f"Has Witness: {tx.has_witness}")
```

#### Transaction Serialization

```python
# Serialize transaction (include witness if available)
raw_bytes = tx.serialize(include_witness=True)
raw_hex = raw_bytes.hex()

# Serialize without witness (for txid calculation)
raw_bytes_no_witness = tx.serialize(include_witness=False)
```

#### Transaction Identifiers

```python
# Get transaction ID (hash without witness)
txid = tx.txid()
print(f"TXID: {txid}")

# Get witness transaction ID (includes witness)
wtxid = tx.wtxid()
print(f"WTXID: {wtxid}")
```

#### Transaction Size

```python
# Calculate transaction size in bytes
size = tx.calculate_size()
print(f"Size: {size} bytes")

# Calculate virtual size (for SegWit, weight/4)
vsize = tx.calculate_vsize()
print(f"Virtual Size: {vsize} bytes")
```

#### Parse Transaction

```python
from tencoinlib.transaction import parse_transaction

# Parse raw transaction hex
raw_hex = "0100000001..."
tx = parse_transaction(raw_hex)

# Access parsed transaction
print(f"TXID: {tx.txid()}")
print(f"Inputs: {len(tx.vin)}")
for i, txin in enumerate(tx.vin):
    print(f"  Input {i}: {txin.prev_txid[:16]}..., vout={txin.vout}")
    if txin.witness:
        print(f"    Witness: {len(txin.witness)} items")

print(f"Outputs: {len(tx.vout)}")
for i, txout in enumerate(tx.vout):
    print(f"  Output {i}: {txout.value} Tenos")
```

---

## Transaction Signing

The library provides comprehensive transaction signing support for all address types:
- **SegWit v0 (P2WPKH)**: Native SegWit addresses (`tc1q...`)
- **Legacy P2PKH**: Pay-to-pubkey-hash addresses (`T...`)
- **Legacy P2SH**: Pay-to-script-hash addresses (`M...`)
- **P2WSH**: SegWit script addresses (multisig, custom scripts)

### TransactionSigner (Universal Signer)

The `TransactionSigner` class automatically detects address types and uses the appropriate signing method. **This is the recommended approach** for most use cases.

#### Sign Transaction with Automatic Detection

```python
from tencoinlib import TransactionSigner, Wallet, TransactionBuilder
from tencoinlib.transaction.address import address_to_script

# Create wallet
wallet = Wallet.create()

# Build transaction with mixed address types
builder = TransactionBuilder()

# Add SegWit input
builder.add_input(
    txid="00" * 32,
    vout=0,
    value=2000000,
    script_pubkey=address_to_script(wallet.get_address())
)

# Add P2PKH input
p2pkh_addr = wallet.get_address("p2pkh")
builder.add_input(
    txid="11" * 32,
    vout=0,
    value=1500000,
    script_pubkey=address_to_script(p2pkh_addr)
)

# Add P2SH input
p2sh_addr = wallet.get_address("p2sh")
builder.add_input(
    txid="22" * 32,
    vout=0,
    value=1000000,
    script_pubkey=address_to_script(p2sh_addr)
)

builder.add_output("tc1q...", 3000000)
builder.set_change_address(wallet.get_address())

tx, fee = builder.build()

# Prepare UTXOs (address type is automatically detected)
utxos = [
    {
        "value": 2000000,
        "script_pubkey": address_to_script(wallet.get_address()),
        "address": wallet.get_address()  # SegWit
    },
    {
        "value": 1500000,
        "script_pubkey": address_to_script(p2pkh_addr),
        "address": p2pkh_addr  # P2PKH
    },
    {
        "value": 1000000,
        "script_pubkey": address_to_script(p2sh_addr),
        "address": p2sh_addr  # P2SH
    }
]

private_keys = [
    bytes.fromhex(wallet.get_private_key_hex()),
    bytes.fromhex(wallet.get_private_key_hex()),
    bytes.fromhex(wallet.get_private_key_hex())
]

# Sign transaction (automatically handles all address types)
signed_tx = TransactionSigner.sign_transaction(tx, utxos, private_keys)

print(f"Transaction ID: {signed_tx.txid()}")
print(f"Has witness: {signed_tx.has_witness}")  # True (has SegWit inputs)
```

#### Sign P2PKH Transaction

```python
from tencoinlib import TransactionSigner, Wallet, TransactionBuilder
from tencoinlib.transaction.address import address_to_script

wallet = Wallet.create()
p2pkh_addr = wallet.get_address("p2pkh")

builder = TransactionBuilder()
builder.add_input(
    txid="abc123...",
    vout=0,
    value=2000000,
    script_pubkey=address_to_script(p2pkh_addr)
)
builder.add_output("T...", 1000000)
builder.set_change_address(p2pkh_addr)

tx, fee = builder.build()

utxos = [{
    "value": 2000000,
    "script_pubkey": address_to_script(p2pkh_addr),
    "address": p2pkh_addr
}]

signed_tx = TransactionSigner.sign_transaction(
    tx, utxos, [bytes.fromhex(wallet.get_private_key_hex())]
)

# P2PKH uses scriptSig (not witness)
print(f"ScriptSig length: {len(signed_tx.vin[0].script_sig)} bytes")
```

#### Sign P2SH Transaction

```python
from tencoinlib import TransactionSigner, Wallet, TransactionBuilder
from tencoinlib.transaction.address import address_to_script

wallet = Wallet.create()
p2sh_addr = wallet.get_address("p2sh")

builder = TransactionBuilder()
builder.add_input(
    txid="def456...",
    vout=0,
    value=2000000,
    script_pubkey=address_to_script(p2sh_addr)
)
builder.add_output("M...", 1000000)
builder.set_change_address(p2sh_addr)

tx, fee = builder.build()

utxos = [{
    "value": 2000000,
    "script_pubkey": address_to_script(p2sh_addr),
    "address": p2sh_addr
    # redeem_script is automatically derived for single-sig P2SH
}]

signed_tx = TransactionSigner.sign_transaction(
    tx, utxos, [bytes.fromhex(wallet.get_private_key_hex())]
)

# P2SH uses scriptSig with redeem script
print(f"ScriptSig length: {len(signed_tx.vin[0].script_sig)} bytes")
```

#### Sign Transaction with Custom P2SH Redeem Script

```python
from tencoinlib import TransactionSigner, TransactionBuilder, build_multisig_script
from tencoinlib.transaction.address import address_to_script, script_to_p2sh_address

# Build multisig redeem script (2-of-3)
pubkeys = [
    bytes.fromhex("02a1b2c3..."),
    bytes.fromhex("03d4e5f6..."),
    bytes.fromhex("0298a7b8...")
]
redeem_script = build_multisig_script(2, pubkeys)

# Get P2SH address
p2sh_addr = script_to_p2sh_address(redeem_script)

builder = TransactionBuilder()
builder.add_input(
    txid="ghi789...",
    vout=0,
    value=5000000,
    script_pubkey=address_to_script(p2sh_addr)
)
builder.add_output("M...", 3000000)
tx, fee = builder.build()

# Provide redeem script for P2SH
utxos = [{
    "value": 5000000,
    "script_pubkey": address_to_script(p2sh_addr),
    "address": p2sh_addr,
    "redeem_script": redeem_script  # Required for multisig P2SH
}]

# For multisig, provide private keys for required signatures
private_keys = [bytes.fromhex("key1..."), bytes.fromhex("key2...")]

signed_tx = TransactionSigner.sign_transaction(tx, utxos, private_keys)
```

### LegacySigner

The `LegacySigner` class handles signing for Legacy address types (P2PKH and P2SH).

#### Sign P2PKH Transaction

```python
from tencoinlib.transaction import LegacySigner, TransactionBuilder
from tencoinlib.transaction.address import address_to_script

wallet = Wallet.create()
p2pkh_addr = wallet.get_address("p2pkh")

builder = TransactionBuilder()
builder.add_input(
    txid="abc123...",
    vout=0,
    value=2000000,
    script_pubkey=address_to_script(p2pkh_addr)
)
builder.add_output("T...", 1000000)
tx, fee = builder.build()

utxos = [{
    "value": 2000000,
    "script_pubkey": address_to_script(p2pkh_addr),
    "address": p2pkh_addr
}]

signed_tx = LegacySigner.sign_transaction(
    tx, utxos, [bytes.fromhex(wallet.get_private_key_hex())]
)
```

#### Sign P2SH Transaction with Redeem Script

```python
from tencoinlib.transaction import LegacySigner, build_p2pkh_script
from tencoinlib.keys.ec import privkey_to_pubkey

wallet = Wallet.create()
p2sh_addr = wallet.get_address("p2sh")
private_key = bytes.fromhex(wallet.get_private_key_hex())
pubkey = privkey_to_pubkey(private_key, compressed=True)

# Build redeem script (P2PKH script)
redeem_script = build_p2pkh_script(pubkey)

builder = TransactionBuilder()
builder.add_input(
    txid="def456...",
    vout=0,
    value=2000000,
    script_pubkey=address_to_script(p2sh_addr)
)
tx, fee = builder.build()

utxos = [{
    "value": 2000000,
    "script_pubkey": address_to_script(p2sh_addr),
    "address": p2sh_addr,
    "redeem_script": redeem_script
}]

signed_tx = LegacySigner.sign_transaction(tx, utxos, [private_key])
```

### SegWitSigner

The `SegWitSigner` class handles signing for SegWit (P2WPKH) transactions using BIP-143.

#### Sign SegWit Transaction

```python
from tencoinlib import SegWitSigner, Wallet, TransactionBuilder
from tencoinlib.transaction.address import address_to_script

wallet = Wallet.create()

builder = TransactionBuilder()
builder.add_input(
    txid="abc123...",
    vout=0,
    value=2000000,
    script_pubkey=address_to_script(wallet.get_address())
)
builder.add_output("tc1q...", 1000000)
tx, fee = builder.build()

utxos = [{
    "value": 2000000,
    "script_pubkey": address_to_script(wallet.get_address()),
    "address": wallet.get_address()  # Must be P2WPKH
}]

signed_tx = SegWitSigner.sign_transaction(
    tx, utxos, [bytes.fromhex(wallet.get_private_key_hex())]
)

# SegWit uses witness (not scriptSig)
print(f"Has witness: {signed_tx.has_witness}")
print(f"Witness items: {len(signed_tx.vin[0].witness)}")
```

#### Sign Single SegWit Input

```python
# Sign a specific input
utxo = {
    "value": 1000000,
    "script_pubkey": bytes.fromhex("..."),
    "address": "tc1q..."
}
private_key = bytes.fromhex("abc123...")

SegWitSigner.sign_input(
    tx=transaction,
    input_index=0,
    utxo=utxo,
    private_key=private_key
)
```

#### Create Witness Signature

```python
# Create witness signature manually
script_code = b"..."  # P2PKH script for the public key hash
signature = SegWitSigner.create_witness_signature(
    tx=transaction,
    input_index=0,
    private_key=private_key,
    script_code=script_code,
    value=1000000,
    sighash_type=1  # SIGHASH_ALL
)
```

#### Verify Witness

```python
# Verify witness signature
is_valid = SegWitSigner.verify_witness(
    tx=transaction,
    input_index=0,
    public_key=b"...",           # 33-byte compressed public key
    script_code=b"...",
    value=1000000,
    witness=[signature, public_key]
)

print(f"Signature valid: {is_valid}")
```

---

## Multisig Transactions

Multisig (multi-signature) transactions require M-of-N participants to sign before funds can be spent. Tencoinlib supports two multisig address types:

- **P2SH multisig** (`M...`): Legacy multisig — redeem script is revealed at spend time.
- **P2WSH multisig** (`tc1q...`): Native SegWit multisig — lower fees, same security model.

Both types support any m-of-n combination from 1-of-1 up to 15-of-15.

### Overview

| Type | Address | Script committed at creation | Signing overhead |
|---|---|---|---|
| P2SH multisig | `M...` | Hash of redeem script | scriptSig |
| P2WSH multisig | `tc1q...` | Hash of witness script | Witness |

### Key Concepts

**Redeem script / Witness script**: The raw multisig script that encodes M, N, and all N public keys. For P2SH this is called the redeem script; for P2WSH it is called the witness script. Both are built with `build_multisig_script()`.

**Script hash**: The on-chain address stores only the hash of this script. The full script must be provided again at spend time.

**Canonical pubkey ordering**: Passing `sort_pubkeys=True` (the default) sorts the public keys lexicographically before embedding them in the script. All participants must use the same ordering, so always sort or always preserve insertion order — never mix.

---

### Building a Multisig Address

#### P2SH Multisig Address (M...)

```python
from tencoinlib.transaction import build_multisig_script, script_to_p2sh_address

# Compressed public keys from each participant (33 bytes each)
pubkeys = [
    bytes.fromhex("02a1b2c3d4e5f6..."),   # Participant 1
    bytes.fromhex("03d4e5f6a1b2c3..."),   # Participant 2
    bytes.fromhex("0298a7b8c9d0e1..."),   # Participant 3
]

# Build 2-of-3 multisig redeem script
redeem_script = build_multisig_script(m=2, pubkeys=pubkeys, sort_pubkeys=True)
print(f"Redeem script ({len(redeem_script)} bytes): {redeem_script.hex()}")

# Derive P2SH address from the redeem script
p2sh_address = script_to_p2sh_address(redeem_script)
print(f"P2SH multisig address: {p2sh_address}")   # M...

# Save the redeem script — you need it to spend funds later
```

#### P2WSH Multisig Address (tc1q...)

```python
from tencoinlib.transaction import build_multisig_script, script_to_p2wsh_address

pubkeys = [
    bytes.fromhex("02a1b2c3d4e5f6..."),
    bytes.fromhex("03d4e5f6a1b2c3..."),
    bytes.fromhex("0298a7b8c9d0e1..."),
]

# Build 2-of-3 multisig witness script (identical call — same function)
witness_script = build_multisig_script(m=2, pubkeys=pubkeys, sort_pubkeys=True)

# Derive P2WSH address (SegWit native — lower fees)
p2wsh_address = script_to_p2wsh_address(witness_script)
print(f"P2WSH multisig address: {p2wsh_address}")  # tc1q...

# Save the witness script — you need it to spend funds later
```

#### Using Wallet.build_multisig_script()

The `Wallet` class provides a convenience static method that also accepts hex strings:

```python
from tencoinlib import Wallet
from tencoinlib.transaction import script_to_p2sh_address, script_to_p2wsh_address

pubkeys_hex = [
    "02a1b2c3d4e5f6...",
    "03d4e5f6a1b2c3...",
    "0298a7b8c9d0e1...",
]

# Accepts both bytes and hex strings
script = Wallet.build_multisig_script(m=2, pubkeys=pubkeys_hex, sort_pubkeys=True)

p2sh_addr  = script_to_p2sh_address(script)
p2wsh_addr = script_to_p2wsh_address(script)

print(f"P2SH : {p2sh_addr}")
print(f"P2WSH: {p2wsh_addr}")
```

---

### Deriving Participant Keys

Each participant in a multisig wallet derives their own key independently. The public keys are then shared and combined to create the multisig address.

```python
from tencoinlib import Wallet
from tencoinlib.keys.ec import privkey_to_pubkey
from tencoinlib.keys.bip32 import derive_path_from_seed

# --- Participant 1 ---
wallet1 = Wallet.create()
seed1 = wallet1.seed
priv1, _ = derive_path_from_seed(seed1, "m/84'/5353'/0'/0/0")
pub1 = privkey_to_pubkey(priv1, compressed=True)

# --- Participant 2 ---
wallet2 = Wallet.create()
seed2 = wallet2.seed
priv2, _ = derive_path_from_seed(seed2, "m/84'/5353'/0'/0/0")
pub2 = privkey_to_pubkey(priv2, compressed=True)

# --- Participant 3 ---
wallet3 = Wallet.create()
seed3 = wallet3.seed
priv3, _ = derive_path_from_seed(seed3, "m/84'/5353'/0'/0/0")
pub3 = privkey_to_pubkey(priv3, compressed=True)

# Participants exchange public keys and build the shared address
from tencoinlib.transaction import build_multisig_script, script_to_p2wsh_address

witness_script = build_multisig_script(m=2, pubkeys=[pub1, pub2, pub3], sort_pubkeys=True)
shared_address = script_to_p2wsh_address(witness_script)

print(f"Shared 2-of-3 P2WSH address: {shared_address}")
print(f"Witness script: {witness_script.hex()}")
```

> **Important**: Every participant must store the complete `witness_script` (or `redeem_script` for P2SH). Without it, funds cannot be recovered. It is not stored on-chain at deposit time.

---

### Signing a Multisig Transaction

#### Private Keys Format

`sign_transaction` accepts three equivalent formats for `private_keys`. All three produce identical results:

```python
# Format 1 — flat list (original single-sig API, one key per input)
# Works only when each input needs exactly one key.
private_keys = [key1, key2]

# Format 2 — nested list (one list of keys per input, recommended for multisig)
private_keys = [
    [key1, key2],       # Input 0: two keys for a 2-of-3 multisig
    [key3],             # Input 1: one key for a single-sig input
]

# Format 3 — mixed (flat bytes and lists in the same list)
private_keys = [
    key_a,              # single key → wrapped automatically to [key_a]
    [key_b, key_c],     # multiple keys for a multisig input
]
```

Additionally, extra co-signer keys can always be attached directly to the UTXO dict instead:

```python
utxo = {
    "address": p2wsh_address,
    "value": 5_000_000,
    "witness_script": witness_script,
    "cosigner_keys": [key2, key3],   # merged with whatever is in private_keys[i]
}
# private_keys[i] = key1   (first key)
# Final set used for signing: {key1, key2, key3}  (deduplicated by pubkey)
```

Both sources of keys are merged and deduplicated automatically — there is no need to avoid overlap.

---

#### P2WSH Multisig Transaction (SegWit, tc1q...)

```python
from tencoinlib import TransactionSigner, TransactionBuilder
from tencoinlib.transaction import (
    build_multisig_script,
    script_to_p2wsh_address,
    address_to_script,
)

# --- Setup (all participants agree on the same script) ---
witness_script = build_multisig_script(m=2, pubkeys=[pub1, pub2, pub3], sort_pubkeys=True)
p2wsh_address  = script_to_p2wsh_address(witness_script)

# --- Build transaction ---
builder = TransactionBuilder()
builder.add_input(
    txid="abcdef1234567890" * 4,         # 64-char hex TXID
    vout=0,
    value=5_000_000,                     # Tenos
    script_pubkey=address_to_script(p2wsh_address)
)
builder.add_output("tc1q...", 4_000_000) # recipient
builder.set_change_address(p2wsh_address)
builder.set_fee_rate(20)

tx, estimated_fee = builder.build()
print(f"Estimated fee: {estimated_fee} Tenos")

# --- Sign (2-of-3: participant 1 and participant 2 sign) ---
utxos = [{
    "address":       p2wsh_address,
    "value":         5_000_000,
    "witness_script": witness_script,    # required for P2WSH
}]

# Nested list: both keys for the single P2WSH input
private_keys = [[priv1, priv2]]

signed_tx = TransactionSigner.sign_transaction(tx, utxos, private_keys)

print(f"TXID          : {signed_tx.txid()}")
print(f"Has witness   : {signed_tx.has_witness}")
print(f"Witness items : {len(signed_tx.vin[0].witness)}")
# witness items = 1 (OP_0 placeholder) + 2 (signatures) + 1 (witness_script) = 4
```

#### P2SH Multisig Transaction (Legacy, M...)

```python
from tencoinlib import TransactionSigner, TransactionBuilder
from tencoinlib.transaction import (
    build_multisig_script,
    script_to_p2sh_address,
    address_to_script,
)

# --- Setup ---
redeem_script = build_multisig_script(m=2, pubkeys=[pub1, pub2, pub3], sort_pubkeys=True)
p2sh_address  = script_to_p2sh_address(redeem_script)

# --- Build transaction ---
builder = TransactionBuilder()
builder.add_input(
    txid="abcdef1234567890" * 4,
    vout=0,
    value=5_000_000,
    script_pubkey=address_to_script(p2sh_address)
)
builder.add_output("tc1q...", 4_000_000)
builder.set_change_address(p2sh_address)

tx, estimated_fee = builder.build()

# --- Sign (2-of-3: participant 1 and participant 2 sign) ---
utxos = [{
    "address":       p2sh_address,
    "script_pubkey": address_to_script(p2sh_address),
    "redeem_script": redeem_script,      # required for P2SH
    "value":         5_000_000,
}]

private_keys = [[priv1, priv2]]

signed_tx = TransactionSigner.sign_transaction(tx, utxos, private_keys)

print(f"TXID           : {signed_tx.txid()}")
print(f"ScriptSig size : {len(signed_tx.vin[0].script_sig)} bytes")
# scriptSig = OP_0 <sig1> <sig2> PUSHDATA1 <len> <redeem_script>
```

---

### Mixed Inputs: Multisig and Single-Sig in One Transaction

`TransactionSigner` handles any combination of address types in a single call. Each input is signed independently according to its own address type.

```python
from tencoinlib import TransactionSigner, TransactionBuilder, Wallet
from tencoinlib.transaction import (
    build_multisig_script,
    script_to_p2wsh_address,
    address_to_script,
)

single_wallet    = Wallet.create()
single_address   = single_wallet.get_address()            # P2WPKH tc1q...
single_priv      = bytes.fromhex(single_wallet.get_private_key_hex())

witness_script   = build_multisig_script(m=2, pubkeys=[pub1, pub2, pub3], sort_pubkeys=True)
multisig_address = script_to_p2wsh_address(witness_script) # P2WSH tc1q...

# --- Build transaction with two inputs ---
builder = TransactionBuilder()

# Input 0: single-sig P2WPKH
builder.add_input(
    txid="aaaa" * 16,
    vout=0,
    value=2_000_000,
    script_pubkey=address_to_script(single_address)
)

# Input 1: 2-of-3 P2WSH multisig
builder.add_input(
    txid="bbbb" * 16,
    vout=1,
    value=3_000_000,
    script_pubkey=address_to_script(multisig_address)
)

builder.add_output("tc1q...", 4_000_000)
builder.set_change_address(single_address)
tx, fee = builder.build()

# --- Sign: flat key for input 0, nested list for input 1 ---
utxos = [
    {
        "address": single_address,
        "value":   2_000_000,
    },
    {
        "address":        multisig_address,
        "value":          3_000_000,
        "witness_script": witness_script,
    },
]

private_keys = [
    single_priv,          # Input 0: one key (flat bytes)
    [priv1, priv2],       # Input 1: two keys (nested list)
]

signed_tx = TransactionSigner.sign_transaction(tx, utxos, private_keys)

print(f"TXID         : {signed_tx.txid()}")
print(f"Has witness  : {signed_tx.has_witness}")     # True
print(f"Input 0 witness items : {len(signed_tx.vin[0].witness)}")  # 2 (P2WPKH)
print(f"Input 1 witness items : {len(signed_tx.vin[1].witness)}")  # 4 (P2WSH 2-of-3)
```

---

### Using cosigner_keys in the UTXO Dict

When co-signers provide their keys through a different code path (e.g., collected over the network), attach them directly to the UTXO dict via `cosigner_keys`. They are merged with the `private_keys` argument automatically.

```python
utxos = [{
    "address":        p2wsh_address,
    "value":          5_000_000,
    "witness_script": witness_script,
    "cosigner_keys":  [priv2, priv3],   # keys from co-signers
}]

# private_keys provides priv1; cosigner_keys adds priv2 and priv3.
# Final set: {priv1, priv2, priv3} — deduplicated by pubkey.
private_keys = [priv1]

signed_tx = TransactionSigner.sign_transaction(tx, utxos, private_keys)
```

> The same `cosigner_keys` field works identically for P2SH multisig inputs.

---

### Complete End-to-End Example

```python
from tencoinlib import Wallet, TransactionSigner, TransactionBuilder
from tencoinlib.transaction import (
    build_multisig_script,
    script_to_p2wsh_address,
    address_to_script,
)
from tencoinlib.keys.ec import privkey_to_pubkey
from tencoinlib.keys.bip32 import derive_path_from_seed
from tencoinlib.rpc import RPCClient
from tencoinlib.constants import TENOS_PER_TEC

# ── 1. Key generation (each participant runs this independently) ──────────
wallet1 = Wallet.create()
wallet2 = Wallet.create()
wallet3 = Wallet.create()

priv1, _ = derive_path_from_seed(wallet1.seed, "m/84'/5353'/0'/0/0")
priv2, _ = derive_path_from_seed(wallet2.seed, "m/84'/5353'/0'/0/0")
priv3, _ = derive_path_from_seed(wallet3.seed, "m/84'/5353'/0'/0/0")

pub1 = privkey_to_pubkey(priv1, compressed=True)
pub2 = privkey_to_pubkey(priv2, compressed=True)
pub3 = privkey_to_pubkey(priv3, compressed=True)

# ── 2. Build shared address (all participants must agree) ─────────────────
witness_script = build_multisig_script(m=2, pubkeys=[pub1, pub2, pub3], sort_pubkeys=True)
multisig_addr  = script_to_p2wsh_address(witness_script)

print(f"2-of-3 P2WSH address : {multisig_addr}")
print(f"Witness script       : {witness_script.hex()}")
print()

# ── 3. (Off-chain) Fund the multisig address, then retrieve UTXOs ─────────
rpc   = RPCClient(host="127.0.0.1", port=10111, token="your-token")
utxos = rpc.list_unspent(multisig_addr)

if not utxos:
    print("No UTXOs found — send funds to the multisig address first.")
    exit(1)

total_available = sum(u["amount"] for u in utxos)
print(f"Available: {total_available / TENOS_PER_TEC:.8f} TEC across {len(utxos)} UTXO(s)")

# ── 4. Build the spending transaction ─────────────────────────────────────
SEND_AMOUNT    = 1_000_000    # 0.01 TEC
recipient_addr = "tc1q..."    # replace with actual recipient

builder = TransactionBuilder()
for u in utxos:
    builder.add_input(
        txid=u["txid"],
        vout=u["vout"],
        value=u["amount"],
        script_pubkey=address_to_script(multisig_addr)
    )
builder.add_output(recipient_addr, SEND_AMOUNT)
builder.set_change_address(multisig_addr)
builder.set_fee_rate(20)

tx, estimated_fee = builder.build()
print(f"Estimated fee: {estimated_fee} Tenos")

# ── 5. Sign (participants 1 and 2 provide signatures) ─────────────────────
utxo_data = [{
    "address":        multisig_addr,
    "value":          u["amount"],
    "witness_script": witness_script,
} for u in utxos]

# Nested list: one key-list per input (all inputs share the same multisig here)
private_keys = [[priv1, priv2]] * len(utxos)

signed_tx = TransactionSigner.sign_transaction(tx, utxo_data, private_keys)

print(f"TXID     : {signed_tx.txid()}")
print(f"Size     : {signed_tx.calculate_size()} bytes")
print(f"vSize    : {signed_tx.calculate_vsize()} bytes")

# ── 6. Validate and broadcast ─────────────────────────────────────────────
tx_hex = signed_tx.serialize().hex()

result = rpc.test_mempool_accept(tx_hex)
if not result.get("allowed"):
    print(f"Transaction rejected: {result.get('reject-reason', 'unknown')}")
    exit(1)

txid = rpc.send_raw_transaction(tx_hex)
print(f"\n✅ Transaction broadcast successfully!")
print(f"TXID: {txid}")
```

---

### Supported m-of-n Combinations

All combinations from 1-of-1 up to 15-of-15 are supported. Practical limits imposed by the Tencoin node's script size policy may apply for very large n.

| m \ n | 1 | 2 | 3 | 5 | 10 | 15 |
|---|---|---|---|---|---|---|
| 1 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 2 | — | ✅ | ✅ | ✅ | ✅ | ✅ |
| 3 | — | — | ✅ | ✅ | ✅ | ✅ |
| 5 | — | — | — | ✅ | ✅ | ✅ |
| 10 | — | — | — | — | ✅ | ✅ |
| 15 | — | — | — | — | — | ✅ |

**Script size and push opcode used for the redeem/witness script in scriptSig:**

| n | Script size | Push opcode |
|---|---|---|
| 1–2 | ≤ 75 bytes | Single byte length prefix |
| 3–7 | 76–255 bytes | `OP_PUSHDATA1` (0x4c) |
| 8–15 | 256–513 bytes | `OP_PUSHDATA2` (0x4d) |

Tencoinlib selects the correct push opcode automatically via `_push_data`.

---

### Error Handling

```python
from tencoinlib import TransactionSigner, SigningError
from tencoinlib.transaction import ScriptError

# Not enough matching private keys for the required m
try:
    signed_tx = TransactionSigner.sign_transaction(tx, utxos, [[priv1]])
    # Will raise if 2-of-3 is required and only 1 key is provided
except SigningError as e:
    print(f"Signing failed: {e}")
    # e.g. "multisig requires 2 signatures but only 1 matching private keys provided"

# Missing witness_script for a P2WSH input
try:
    signed_tx = TransactionSigner.sign_transaction(
        tx,
        [{"address": p2wsh_address, "value": 1_000_000}],   # no witness_script
        [priv1]
    )
except SigningError as e:
    print(f"Signing failed: {e}")
    # "P2WSH input UTXO must contain 'witness_script'"

# Invalid multisig parameters
try:
    from tencoinlib.transaction import build_multisig_script
    build_multisig_script(m=5, pubkeys=[pub1, pub2])   # m > n
except ScriptError as e:
    print(f"Script error: {e}")
    # "m and n must be 1..16 and m <= n"
```

---

### Best Practices for Multisig

1. **Always store the full script** — the redeem script (P2SH) or witness script (P2WSH) is not stored on-chain at deposit time. Every participant should back it up independently.

2. **Use `sort_pubkeys=True` consistently** — all participants must build the script with the same pubkey order. Sorting guarantees determinism regardless of insertion order.

3. **Prefer P2WSH over P2SH** — P2WSH uses the witness field, which is discounted in vSize calculation. For large multisig scripts (n ≥ 3) the fee saving is significant.

4. **Verify the address before sending funds** — all participants should independently derive the multisig address from the agreed script and confirm it matches before depositing.

5. **Test on small amounts first** — always send a small test amount, verify you can spend it, then use the address for larger amounts.

6. **Use `test_mempool_accept` before broadcasting** — validates the signed transaction against node policy without risking a broadcast failure.

   ```python
   result = rpc.test_mempool_accept(signed_tx.serialize().hex())
   if result.get("allowed"):
       txid = rpc.send_raw_transaction(signed_tx.serialize().hex())
   ```

---

## RPC Client

The `RPCClient` class provides methods to interact with Tencoin nodes via JSON-RPC.

### Connection Setup

```python
from tencoinlib.rpc import RPCClient

# Simple connection (default settings)
rpc = RPCClient()

# Full configuration
rpc = RPCClient(
    host="127.0.0.1",        # Node hostname or IP
    port=10111,              # RPC port (default: 10111)
    token="your-token",      # RPC authentication token
    timeout=30,              # Request timeout in seconds
    use_ssl=False            # Use HTTPS instead of HTTP
)
```

### Wallet Methods

#### Get Balance

```python
# Get balance for an address
address = "tc1q..."
balance = rpc.get_balance(address)
print(f"Balance: {balance} Tenos")
print(f"Balance: {balance / 100000000} TEC")
```

#### List Unspent Outputs (UTXOs)

```python
# Get unspent outputs for an address
utxos = rpc.list_unspent(address, minconf=1)

for utxo in utxos:
    print(f"TXID: {utxo['txid']}")
    print(f"Vout: {utxo['vout']}")
    print(f"Amount: {utxo['amount']} Tenos")
    print(f"Confirmations: {utxo.get('confirmations', 0)}")
    print(f"ScriptPubKey: {utxo.get('scriptPubKey', '')}")
    print("---")
```

### Transaction Methods

#### Send Raw Transaction

```python
# Broadcast a raw transaction
tx_hex = "0100000001..."
txid = rpc.send_raw_transaction(tx_hex)
print(f"Transaction ID: {txid}")
```

#### Test Mempool Acceptance

```python
# Test if transaction would be accepted to mempool
result = rpc.test_mempool_accept(tx_hex)
print(f"Acceptable: {result}")
```

#### Get Transaction Information

```python
# Get transaction details
txid = "abc123..."
tx_info = rpc.get_transaction(txid)
print(tx_info)
```

#### Get Raw Transaction

```python
# Get raw transaction hex
raw_tx = rpc.get_raw_transaction(txid)
print(f"Raw Transaction: {raw_tx}")
```

#### Decode Raw Transaction

```python
# Decode raw transaction
decoded = rpc.decode_raw_transaction(tx_hex)
print(decoded)
# {
#     "txid": "...",
#     "version": 1,
#     "vin": [...],
#     "vout": [...],
#     ...
# }
```

### Blockchain Methods

#### Get Block Count

```python
# Get current block height
height = rpc.get_block_count()
print(f"Current Block Height: {height}")
```

#### Get Best Block Hash

```python
# Get hash of best block
best_hash = rpc.get_best_block_hash()
print(f"Best Block Hash: {best_hash}")
```

#### Get Block Information

```python
# Get block by height
block_info = rpc.get_block(height=1000)

# Get block by hash
block_info = rpc.get_block(block_hash="abc123...")

# Block information includes:
# - hash
# - height
# - time
# - transactions
# - ...
```

#### Get Block Header

```python
# Get block header only
block_hash = "abc123..."
header = rpc.get_block_header(block_hash)
```

#### Get Blockchain Info

```python
# Get blockchain information
info = rpc.get_blockchain_info()
print(f"Chain: {info.get('chain')}")
print(f"Blocks: {info.get('blocks')}")
print(f"Difficulty: {info.get('difficulty')}")
```

#### Get Mempool Info

```python
# Get mempool information
mempool_info = rpc.get_mempool_info()
print(f"Size: {mempool_info.get('size', 0)} transactions")
print(f"Bytes: {mempool_info.get('bytes', 0)} bytes")
```

#### Get Raw Mempool

```python
# Get raw mempool transactions
raw_mempool = rpc.get_raw_mempool()
print(f"Transactions in mempool: {len(raw_mempool)}")
```

### Network Methods

#### Get Network Info

```python
# Get network information
network_info = rpc.get_network_info()
print(f"Version: {network_info.get('version')}")
print(f"Subversion: {network_info.get('subversion')}")
```

#### Get Peer Info

```python
# Get peer information
peers = rpc.get_peer_info()
for peer in peers:
    print(f"Address: {peer.get('addr')}")
    print(f"Connected: {peer.get('connected')}")
    print(f"Version: {peer.get('version')}")
```

### Mining Methods

#### Get Work

```python
# Get work for mining
work = rpc.get_work()
print(work)
```

#### Submit Block

```python
# Submit a mined block
block_hex = "01000000..."
result = rpc.submit_block(block_hex)
print(result)
```

### Utility Methods

#### Validate Address

```python
# Validate a Tencoin address
result = rpc.validate_address("tc1q...")
print(f"Valid: {result.get('isvalid', False)}")
print(f"Address: {result.get('address')}")
```

#### Estimate Fee

```python
# Estimate fee for target confirmation blocks
fee_estimate = rpc.estimate_fee(blocks=6)
print(f"Fee Estimate: {fee_estimate}")
```

#### Get Difficulty

```python
# Get current difficulty
difficulty = rpc.get_difficulty()
print(difficulty)
```

### Get Public Key (`getpublickey`)

**What it does.** Give it an address (like `tc1q...` or one starting with a letter) and the node searches the whole blockchain for the **public key** of that address.

**Why it is needed.** On Bitcoin-like chains an address is only the hash of a public key (a 20-byte code). The key itself is not in the address. It appears on-chain only at the moment an output of that address is **spent** (inside the `scriptSig` or the `witness`). So:

- address spent at least once → the key is on-chain and can be found;
- address never spent → the key is not on-chain; nothing can be found (ask the owner for the key).

```python
from tencoinlib.rpc import RPCClient, PublicKeyNotFoundError

rpc = RPCClient(host="127.0.0.1", port=10111, token="your-token")

try:
    info = rpc.get_public_key("tc1q...")
    print(info.public_key_hex)     # e.g. 02abc123...
    print(info.format)             # "compressed" or "uncompressed"
    print(info.txid, info.input_index, info.location, info.height)   # where it was revealed
    key = info.compressed          # 33 bytes: what TMSG encryption uses
except PublicKeyNotFoundError:
    print("This address has never been used as a spending input.")
```

**Node command.** The client sends `{"command": "getpublickey", "params": {"address": "tc1q..."}}`.

Found:

```json
{
  "success": true,
  "address": "tc1q...",
  "public_key": "02abc123...",
  "format": "compressed",
  "source": { "txid": "...", "input_index": 0, "location": "witness", "height": 12345 },
  "verified": true
}
```

Not found:

```json
{ "success": false, "error": "No public key found for this address (it has never been used as a spending input)." }
```

**The answer is verified locally.** The library never trusts the node blindly: the returned key must be a valid point and must hash to the requested address (P2PKH with a compressed or uncompressed key, P2WPKH, or P2SH-P2WPKH). Otherwise `PublicKeyVerificationError` is raised and the key is not used. This matters for TMSG: a wrong key would encrypt your message to someone else.

`public_key_matches_address(pubkey, address)` and `compress_public_key(pubkey)` are available from `tencoinlib.rpc`.

---

## Address Utilities

### Address Validation

```python
from tencoinlib.transaction import is_valid_address, get_address_type

address = "tc1q..."

# Check if address is valid
if is_valid_address(address):
    print("Address is valid")
    
    # Get address type
    addr_type = get_address_type(address)
    print(f"Address type: {addr_type}")
    # Possible values: "p2wpkh", "p2pkh", "p2sh", "p2wsh"
else:
    print("Address is invalid")
```

### Decode Address

```python
from tencoinlib.transaction import decode_address

address = "tc1q..."
addr_type, hash_bytes = decode_address(address)

print(f"Type: {addr_type}")
print(f"Hash: {hash_bytes.hex()}")
```

### Address to ScriptPubKey

```python
from tencoinlib.transaction import address_to_script

address = "tc1q..."
script_pubkey = address_to_script(address)
print(f"ScriptPubKey: {script_pubkey.hex()}")
```

### Supported Address Types

The library supports multiple address types:

- **P2WPKH** (tc1q...): SegWit version 0 pay-to-witness-public-key-hash
- **P2PKH**: Pay-to-public-key-hash (legacy)
- **P2SH**: Pay-to-script-hash
- **P2WSH**: Pay-to-witness-script-hash

**Note**: Wallet creation only generates P2WPKH addresses, but you can create transactions to/from any address type.

---

## Fee Management

### FeeCalculator

The `FeeCalculator` class provides methods for calculating transaction fees.

#### Estimate Transaction Size

```python
from tencoinlib.transaction import FeeCalculator

# Estimate size for SegWit transaction
size = FeeCalculator.estimate_size(
    num_inputs=2,
    num_outputs=2,
    has_segwit=True
)
print(f"Estimated size: {size} bytes")

# Estimate size for Legacy transaction
size = FeeCalculator.estimate_size(
    num_inputs=2,
    num_outputs=2,
    has_segwit=False
)
```

#### Calculate Fee

```python
# Calculate fee for transaction
fee = FeeCalculator.calculate_fee(
    num_inputs=2,
    num_outputs=2,
    fee_rate=20,          # Tenos per byte
    has_segwit=True
)
print(f"Fee: {fee} Tenos")

# Use default fee rate
fee = FeeCalculator.calculate_fee(
    num_inputs=1,
    num_outputs=1,
    has_segwit=True
)
```

#### Calculate Fee for Transaction Object

```python
from tencoinlib.transaction import Transaction

tx = Transaction(...)  # Your transaction
fee = FeeCalculator.calculate_fee_for_transaction(tx, fee_rate=20)
print(f"Fee: {fee} Tenos")
```

#### Recommended Fee Rates

```python
# Get recommended fee rates
rates = FeeCalculator.get_recommended_fee_rates()
print(f"Priority: {rates['priority']} Tenos/byte")
print(f"Normal: {rates['normal']} Tenos/byte")
print(f"Economy: {rates['economy']} Tenos/byte")
```

### Fee Constants

```python
from tencoinlib.transaction import FeeCalculator

FeeCalculator.DEFAULT_FEE_RATE    # 20 Tenos/byte
FeeCalculator.PRIORITY_FEE_RATE   # 50 Tenos/byte
FeeCalculator.ECONOMY_FEE_RATE    # 10 Tenos/byte
```

### Setting Fees in TransactionBuilder

```python
builder = TransactionBuilder()

# Use default fee rate (20 Tenos/byte)
builder.add_input(...)
builder.add_output(...)
tx, fee = builder.build()

# Set custom fee rate
builder.set_fee_rate(50)  # Higher fee for faster confirmation
tx, fee = builder.build()

# Use recommended rates
from tencoinlib.transaction import FeeCalculator
builder.set_fee_rate(FeeCalculator.PRIORITY_FEE_RATE)
```

### set_fee() — Fixed Fee with Unit

Use `set_fee()` to set an exact fixed fee instead of a per-byte rate.
The `unit` parameter controls how the value is interpreted.

#### Unit: TEC

Pass a float value in TEC. The builder converts it to Tenos internally (multiplied by `100_000_000`).

```python
builder.set_fee(0.0022, unit="TEC")   # → 220_000 Tenos
builder.set_fee(0.001,  unit="TEC")   # → 100_000 Tenos
builder.set_fee(0.0,    unit="TEC")   # → 0 Tenos (zero-fee)
```

#### Unit: Teno

Pass an integer value in Tenos directly. No conversion is applied.

```python
builder.set_fee(220000, unit="Teno")  # → 220_000 Tenos
builder.set_fee(1000,   unit="Teno")  # → 1_000 Tenos
builder.set_fee(0,      unit="Teno")  # → 0 Tenos (zero-fee)
```

#### Unit is Case-Insensitive

All of the following are equivalent:

```python
builder.set_fee(0.0022, unit="TEC")
builder.set_fee(0.0022, unit="tec")
builder.set_fee(0.0022, unit="Tec")

builder.set_fee(220000, unit="Teno")
builder.set_fee(220000, unit="teno")
builder.set_fee(220000, unit="TENO")
```

---

### Timelock Outputs

Use `add_timelock_output()` to create outputs that cannot be spent until a certain block height or timestamp is reached.

#### Lock by Block Height

The output is spendable only after the blockchain reaches `lock_height`.

```python
builder.add_timelock_output(
    address="tc1q...",
    amount=1000000,
    lock_height=200_000,   # Spendable after block 200,000
)
```

#### Lock by Timestamp

The output is spendable only after the given Unix timestamp.

```python
builder.add_timelock_output(
    address="tc1q...",
    amount=1000000,
    lock_timestamp=1_830_297_600,   # Spendable after that Unix time
)
```

> **Note**: Provide either `lock_height` or `lock_timestamp` — not both.

---

## Key Management

### BIP-39 Mnemonic

```python
from tencoinlib.keys.bip39 import (
    generate_mnemonic,
    validate_mnemonic,
    mnemonic_to_seed,
    mnemonic_to_entropy
)

# Generate mnemonic
mnemonic = generate_mnemonic(strength=128)  # 12 words
print(mnemonic)

# Validate mnemonic
if validate_mnemonic(mnemonic):
    print("Valid mnemonic")

# Convert mnemonic to seed
seed = mnemonic_to_seed(mnemonic, passphrase="")

# Convert mnemonic to entropy
entropy = mnemonic_to_entropy(mnemonic)
```

### BIP-32 Key Derivation & Extended Keys

Low-level BIP-32 helpers are available if you need direct access to extended keys:

```python
from tencoinlib.keys.bip32 import (
    ExtendedPrivateKey,
    ExtendedPublicKey,
    derive_path_from_seed,
)

seed = b"..."  # 64-byte seed
path = "m/84'/5353'/0'/0/0"

# Derive raw key + chain code from seed
private_key, chain_code = derive_path_from_seed(seed, path)

# Create master extended private key from seed
master_xprv = ExtendedPrivateKey.from_seed(seed)
master_xprv_str = master_xprv.to_xprv()
master_xpub_str = master_xprv.to_public().to_xpub()

# Derive account-level xprv/xpub (e.g., m/84'/5353'/0')
account_xprv = master_xprv.derive_path("m/84'/5353'/0'")
account_xpub = account_xprv.to_public()

print(account_xprv.to_xprv())
print(account_xpub.to_xpub())
```

### BIP-44 Address Derivation

```python
from tencoinlib.keys.bip44 import (
    derive_bip44_address_from_seed,
    public_key_to_p2pkh,
    get_account_xprv_from_seed,
    get_account_xpub_from_seed,
    bip44_account_path,
    bip44_address_path,
)

seed = b"..."  # 64-byte seed

# Derive legacy P2PKH address: m/44'/5353'/account'/change/index
private_key, address = derive_bip44_address_from_seed(
    seed,
    account=0,
    change=0,
    index=0
)

# Convert public key to P2PKH address directly
from tencoinlib.keys.ec import privkey_to_pubkey
public_key = privkey_to_pubkey(private_key, compressed=True)
address = public_key_to_p2pkh(public_key)

# Account-level xprv/xpub at m/44'/5353'/account'
account_xprv = get_account_xprv_from_seed(seed, account=0)
account_xpub = get_account_xpub_from_seed(seed, account=0)

# Path helpers
print(bip44_account_path(0))            # "m/44'/5353'/0'"
print(bip44_address_path(0, 0, 5))      # "m/44'/5353'/0'/0/5"
```

### BIP-49 Address Derivation

```python
from tencoinlib.keys.bip49 import (
    derive_bip49_address_from_seed,
    public_key_to_p2sh_segwit,
    get_account_xprv_from_seed,
    get_account_xpub_from_seed,
    bip49_account_path,
    bip49_address_path,
)

seed = b"..."  # 64-byte seed

# Derive nested SegWit (P2SH-P2WPKH) address: m/49'/5353'/account'/change/index
private_key, address = derive_bip49_address_from_seed(
    seed,
    account=0,
    change=0,
    index=0
)

# Convert public key to P2SH-P2WPKH address directly
from tencoinlib.keys.ec import privkey_to_pubkey
public_key = privkey_to_pubkey(private_key, compressed=True)
address = public_key_to_p2sh_segwit(public_key)

# Account-level xprv/xpub at m/49'/5353'/account'
account_xprv = get_account_xprv_from_seed(seed, account=0)
account_xpub = get_account_xpub_from_seed(seed, account=0)

# Path helpers
print(bip49_account_path(0))            # "m/49'/5353'/0'"
print(bip49_address_path(0, 0, 5))      # "m/49'/5353'/0'/0/5"
```

> BIP-44, BIP-49, and BIP-84 use independent purpose fields (44', 49',
> 84') and therefore never share a derivation branch — deriving a P2SH
> address does not touch the same path as a P2WPKH address, and vice
> versa. See [Account-Level Keys](#account-level-keys-bip-44--bip-49--bip-84)
> for the equivalent `Wallet`-level API.

### BIP-84 Address Derivation

```python
from tencoinlib.keys.bip84 import (
    derive_bip84_address_from_seed,
    public_key_to_segwit_v0
)

seed = b"..."  # 64-byte seed

# Derive address
private_key, address = derive_bip84_address_from_seed(
    seed,
    account=0,
    change=0,
    index=0
)

# Convert public key to SegWit address
from tencoinlib.keys.ec import privkey_to_pubkey
public_key = privkey_to_pubkey(private_key, compressed=True)
address = public_key_to_segwit_v0(public_key)
```

### EC Operations

```python
from tencoinlib.keys.ec import (
    privkey_to_pubkey,
    sign,
    verify
)

private_key = bytes.fromhex("...")

# Get public key
public_key = privkey_to_pubkey(private_key, compressed=True)

# Sign message hash
msg_hash = b"..."  # 32-byte hash
signature = sign(private_key, msg_hash)

# Verify signature
is_valid = verify(public_key, msg_hash, signature)
```

---

## Message Signing

Tencoinlib provides Bitcoin Core–compatible message signing and verification through the `tencoinlib.message` module. This allows users to cryptographically prove ownership of an address by signing arbitrary messages with the corresponding private key — without broadcasting any transaction.

### Overview

The implementation follows the same standard used in Bitcoin Core:

- The message is prefixed with `\x18Tencoin Signed Message:\n` before hashing.
- The digest is computed as `SHA256(SHA256(prefix + varint(len) + message))`.
- Signing uses a **recoverable ECDSA signature** (secp256k1), which allows the verifier to reconstruct the public key directly from the signature — no prior knowledge of the public key is required.
- The output is a **65-byte Base64-encoded** signature: `r[32] + s[32] + recovery_byte[1]`.
- Recovery bytes `31–34` indicate a **compressed** public key (standard for Tencoin).

> **Dependency**: Message signing requires `coincurve`. Install it with:
> ```bash
> pip install coincurve
> ```

### Importing

```python
from tencoinlib.message import (
    sign_message,
    verify_message,
    recover_address_from_signature,
    MessageSigningError,
)

# Or directly from the top-level package
from tencoinlib import (
    sign_message,
    verify_message,
    recover_address_from_signature,
    MessageSigningError,
)
```

### Signing a Message

```python
from tencoinlib import Wallet, sign_message, recover_address_from_signature

# Create or recover a wallet
wallet = Wallet.create()
private_key = bytes.fromhex(wallet.get_private_key_hex())

# Define the message to sign
message = "I am the owner of this Tencoin address."

# Sign the message
signature = sign_message(private_key, message)

# Recover the corresponding P2PKH address from the signature
address = recover_address_from_signature(message, signature)

print(f"Address   : {address}")
print(f"Message   : {message}")
print(f"Signature : {signature}")
```

**Example output:**

```
Address   : TxK9mR3...
Message   : I am the owner of this Tencoin address.
Signature : H3k9mR2...  (88-character Base64 string)
```

### Verifying a Message

```python
from tencoinlib import verify_message

address   = "TxK9mR3..."     # The claimed address
message   = "I am the owner of this Tencoin address."
signature = "H3k9mR2..."     # Base64 signature from sign_message()

is_valid = verify_message(address, message, signature)

if is_valid:
    print("✓ Signature is valid — message was signed by the owner of this address.")
else:
    print("✗ Signature is invalid.")
```

### Recovering the Signer's Address

When you only have the message and signature (but not the address), you can recover the signer's address directly:

```python
from tencoinlib import recover_address_from_signature

message   = "I am the owner of this Tencoin address."
signature = "H3k9mR2..."

address = recover_address_from_signature(message, signature)

if address:
    print(f"Signer's address: {address}")
else:
    print("Address recovery failed — invalid signature.")
```

### Signing File Hashes

A common use case is proving ownership of a file by signing its SHA256 hash:

```python
import hashlib
from tencoinlib import Wallet, sign_message, verify_message

def hash_file(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

wallet = Wallet.create()
private_key = bytes.fromhex(wallet.get_private_key_hex())

# Hash the file and sign its hex digest as a message
file_hash = hash_file("document.pdf")
signature = sign_message(private_key, file_hash)

print(f"File SHA256 : {file_hash}")
print(f"Signature   : {signature}")

# Verify later
is_valid = verify_message(wallet.get_address("p2pkh"), file_hash, signature)
print(f"Valid: {is_valid}")
```

### Error Handling

```python
from tencoinlib import sign_message, verify_message, MessageSigningError

# Signing
try:
    signature = sign_message(private_key, message)
except MessageSigningError as e:
    print(f"Signing failed: {e}")

# Verification
try:
    is_valid = verify_message(address, message, signature)
except MessageSigningError as e:
    # Raised for malformed signatures (invalid Base64, wrong length, bad recovery byte)
    print(f"Verification error: {e}")
```

Common causes of `MessageSigningError`:

| Cause | Description |
|---|---|
| `coincurve` not installed | Install with `pip install coincurve` |
| Private key is not 32 bytes | Must be exactly 32 bytes |
| Invalid Base64 signature | Signature string is malformed |
| Signature length ≠ 65 bytes | Decoded bytes must be exactly 65 |
| Invalid recovery byte | Must be in the range 27–34 |

### Address Compatibility

Message signing only supports **P2PKH addresses** (`T...`). SegWit addresses (`tc1q...`) and P2SH addresses (`M...`) are not supported by the message signing standard, consistent with Bitcoin Core behavior.

```python
from tencoinlib import Wallet, sign_message, recover_address_from_signature

wallet = Wallet.create()
private_key = bytes.fromhex(wallet.get_private_key_hex())

# Use P2PKH address for message signing
p2pkh_address = wallet.get_address("p2pkh")   # T...

signature = sign_message(private_key, "Hello Tencoin!")
recovered  = recover_address_from_signature("Hello Tencoin!", signature)

assert recovered == p2pkh_address  # Always holds for the same key
```

### Recovery Byte and Signature Format

The recovery byte encodes both the parity of the public key's Y coordinate and whether the key is compressed:

| Recovery byte | Meaning |
|---|---|
| 31–34 | Compressed public key (standard for Tencoin) |
| 27–30 | Uncompressed public key (legacy compatibility) |

Unlike Bitcoin (which almost exclusively produces `H` or `I` signatures due to its `0x00` address version byte), Tencoin uses version byte `0x41`, which allows all four values — `H`, `I`, `J`, `K` — to appear depending on the key. This is expected behavior and does not affect validity.

---

## HASHLOCK (C2) Outputs

A **HASHLOCK** output (flag byte `0xC2`) locks funds behind a secret. This section covers the secrets themselves (`TCS-...`), **creating** a HASHLOCK output and **spending** one.

### Overview

On-chain layout of a HASHLOCK output:

```
[value 8 B][0xC2][secret_hash 32 B][varint script_len][script_pubkey]
```

- `secret_hash` is `SHA-256(preimage)` — a **single** round, not double.
- The preimage is 1–64 bytes (`HASHLOCK_MIN_PREIMAGE` / `HASHLOCK_MAX_PREIMAGE`).
- `script_pubkey` is an ordinary owner script (P2PKH or P2WPKH). **Spending needs both the owner's signature and the preimage** — knowing the secret alone is not enough, and owning the key alone is not enough.
- The node checks `SHA-256(preimage) == secret_hash`. The preimage is the **last** unlocking item:

| Owner script | Unlocking data |
|---|---|
| P2WPKH (`tc1q...`) | `witness = [signature, pubkey, preimage]` |
| P2PKH (`T...`) | `scriptSig = <signature> <pubkey> <preimage>` |

The signature is the normal BIP-143 (P2WPKH) or legacy (P2PKH) signature of the owner script with `SIGHASH_ALL`. Outputs are hashed with their own `serialize()`, so conditional outputs are committed to exactly as they appear on the wire.

> **Important**: once a spending transaction is broadcast, the preimage is public (it is in the transaction). Use a fresh secret for every lock.

### TCS Secrets

A Tencoin secret (TCS) is the text a hash-locked payment is locked with:

```
TCS-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXCCCCC
prefix (4) + 55 random characters (A-Z, 0-9) + 5 checksum characters = 64 characters
```

- The random part comes from the operating system's CSPRNG.
- The checksum is the first 5 characters (upper case) of the hex digest of `SHA-256("TCS-" + random_part)`. It only exists to catch typos.
- The **whole 64-character text** — prefix and checksum included — is the preimage. Nothing is case-folded, re-grouped or normalised.
- The checksum is enforced only for text that starts with the exact upper-case prefix `TCS-`. Such text with a wrong length, wrong characters or a wrong checksum is refused. Any other text (including `tcs-...` in another case, which only produces a soft warning) is a free-form manual secret and is never checked.
- The secret text is stripped at both ends and encoded as UTF-8; the result must be 1–64 bytes.

```python
from tencoinlib import (
    generate_secret, validate_secret, secret_to_preimage, hash_preimage,
    soft_warnings,
)

secret = generate_secret()            # "TCS-" + 55 chars + 5-char checksum
validate_secret(secret)               # True

preimage = secret_to_preimage(secret)   # bytes — what goes on-chain when spending
secret_hash = hash_preimage(secret)     # 32 bytes — what goes into the output when locking

# Free-form secrets work too (no checksum check):
secret_to_preimage("my secret phrase")  # b"my secret phrase"
```

> **Never log a whole secret.** Log at most its first 8 characters, or its hash.

### Creating a HASHLOCK Output

Use `TransactionBuilder.add_hashlock_output()`. Pass **either** `preimage` (the builder hashes it) **or** `secret_hash` (if you do not want the builder to see the secret).

```python
from tencoinlib import TransactionBuilder, generate_secret, hash_preimage

secret = generate_secret()          # keep it safe — you need it to unlock the funds

builder = TransactionBuilder()
builder.add_input(txid, vout, value, script_pubkey)

# `address` is the OWNER: the only key that can later claim the funds
# (together with the secret).
builder.add_hashlock_output(
    address="tc1q...",
    amount=1_000_000,
    secret_hash=hash_preimage(secret),
)
builder.set_change_address("tc1q...")

tx, fee = builder.build()
```

To let someone else claim the funds, lock to **their** address and give them the secret. To be spendable with this library the owner must be a P2PKH or P2WPKH address.

### Spending a HASHLOCK Output

#### The UTXO dictionary

All spending functions take the HASHLOCK UTXO as a dictionary:

| Key | Type | Description |
|---|---|---|
| `txid` | `str` | Funding transaction ID (64 hex chars) |
| `vout` | `int` | Output index |
| `value` | `int` | Value in **Tenos** |
| `script_pubkey` | `bytes` or hex `str` | The owner script (P2PKH or P2WPKH). If missing, `address` is used instead. (`scriptPubKey` is accepted too.) |
| `secret_hash` | `bytes` or hex `str` | The 32-byte hash committed by the output (`hashlock` is accepted too). **Required**, so the secret can be verified before signing |
| `condition_flag` | `int` (optional) | If present, must be `0xC2` |

You can build it from the funding transaction:

```python
from tencoinlib import parse_transaction

funding = parse_transaction(rpc.get_raw_transaction(txid))   # raw hex of the funding tx
out = funding.vout[0]                                         # a HashlockTxOut

utxo = {
    "txid": funding.txid(),
    "vout": 0,
    "value": out.value,
    "script_pubkey": out.script_pubkey.hex(),
    "secret_hash": out.secret_hash.hex(),
}
```

#### One call: `wallet.spend_hashlock()`

```python
from tencoinlib import Wallet

wallet = Wallet.load("my_wallet.tcw")

with wallet.unlocked(password):
    result = wallet.spend_hashlock(
        utxo,
        destination="tc1q...",
        secret=tcs_secret,            # TCS-... / free-form text (str), or raw preimage (bytes)
    )

print(result.txid, result.fee)
txid = rpc.send_raw_transaction(result.raw_transaction)
```

`spend_hashlock()` validates the UTXO, verifies the secret, builds the transaction, signs it and finalizes it. It returns a `HashlockSpendResult`:

| Field | Description |
|---|---|
| `tx` | The signed `Transaction` object |
| `raw_transaction` | Hex string, ready for `send_raw_transaction` |
| `txid` | Transaction ID |
| `fee` | Fee in Tenos (includes any sub-dust remainder) |
| `amount` | Tenos sent to `destination` |
| `change` | Tenos returned to `change_address` (`0` if none) |
| `secret_hash` | Hex of the verified hash |

**Amount, fee and change**

```python
# Sweep the whole UTXO (default): amount = value - fee
wallet.spend_hashlock(utxo, "tc1q...", secret=secret)

# Send part of it and return the rest as change
wallet.spend_hashlock(
    utxo, "tc1q...",
    amount=1_000_000,
    change_address="tc1q...",
    secret=secret,
)

# Exact fee (Tenos) or a fee rate (Tenos per vbyte)
wallet.spend_hashlock(utxo, "tc1q...", fee=2_000, secret=secret)
wallet.spend_hashlock(utxo, "tc1q...", fee_rate=30, secret=secret)
```

- If `fee` is not given it is estimated as `max(vsize × fee_rate, MIN_RELAY_FEE)`, where the size already includes the signature, public key and preimage. The default rate is `FeeCalculator.DEFAULT_FEE_RATE`.
- If `amount` is given and the remainder is **at least `DUST_LIMIT`**, `change_address` is required — otherwise the build is refused instead of silently burning the remainder as fee.
- A remainder below `DUST_LIMIT` is added to the fee.

**Which key signs.** The wallet signs with the key that provably owns the UTXO: it compares the HASH160 of its candidate keys with the owner script. Candidates are the canonical key, plus (seed wallets) the BIP-84 and BIP-44 keys at `account` / `change` / `index`. For addresses other than the first one pass the position they were derived from:

```python
wallet.spend_hashlock(utxo, "tc1q...", secret=secret, account=0, change=0, index=3)
```

If no key of the wallet owns the UTXO, `HashlockSpendSigningError` is raised and nothing is signed. Watch-only wallets cannot sign (`WalletError`), and locked wallets raise `WalletLockedError`.

#### Step by step

```python
from tencoinlib import (
    build_hashlock_spend, finalize_hashlock_spend, verify_hashlock_secret,
)

# 1. (optional) check the secret first:
#    False  -> wrong secret
#    raises InvalidHashlockSecretError -> typo / bad TCS checksum / empty / too long
assert verify_hashlock_secret(tcs_secret, utxo["secret_hash"])

# 2. build the unsigned transaction
tx = build_hashlock_spend(utxo, "tc1q...", secret=tcs_secret)

# 3. sign input 0 and place the preimage in the unlocking data
with wallet.unlocked(password):
    wallet.sign_hashlock_spend(tx, 0, utxo, tcs_secret)

# 4. final checks + raw hex
raw_tx = finalize_hashlock_spend(tx)
rpc.send_raw_transaction(raw_tx)
```

- `build_hashlock_spend(...)` takes the same `amount`, `fee`, `fee_rate` and `change_address` options as above. `secret` is optional there; if given it is verified against the UTXO and its real size is used for the fee estimate (otherwise 64 bytes are assumed).
- `sign_hashlock_spend()` needs the `utxo` as well as the transaction, because the signature commits to the UTXO's value and owner script and because the secret is checked against its `secret_hash` first. It modifies `tx` in place and also returns it.
- `finalize_hashlock_spend()` refuses transactions with an unsigned input, serializes with the library's own `Transaction.serialize()` and re-parses the result to make sure it round-trips.

#### Without a Wallet

If you hold the private key yourself:

```python
from tencoinlib import spend_hashlock

result = spend_hashlock(
    utxo,
    private_key,                # 32 bytes
    "tc1q...",
    secret=tcs_secret,
)
```

`sign_hashlock_input(tx, input_index, utxo, private_key, secret)` is the matching low-level signer. It checks that the key owns the UTXO and that input `input_index` really spends this UTXO's outpoint.

#### Transactions with Several Inputs

Each hashlock input is signed separately with `sign_hashlock_input()` / `wallet.sign_hashlock_spend()`. Sign the **ordinary** inputs first: `TransactionSigner.sign_transaction()` returns a copy of the transaction that does not keep witnesses already present on other inputs.

```python
from tencoinlib import TransactionBuilder, SegWitSigner, finalize_hashlock_spend

builder = TransactionBuilder()
builder.add_input(plain_txid, 0, plain_value, plain_script)                    # ordinary P2WPKH input (index 0)
builder.add_input(utxo["txid"], utxo["vout"], utxo["value"],
                  bytes.fromhex(utxo["script_pubkey"]))                        # HASHLOCK input (index 1)
builder.add_output("tc1q...", amount)
builder.set_fee(fee)
tx, _ = builder.build()

SegWitSigner.sign_p2wpkh_input(tx, 0, {"value": plain_value}, plain_key)        # ordinary input first
wallet.sign_hashlock_spend(tx, 1, utxo, tcs_secret)                            # then the HASHLOCK input
raw_tx = finalize_hashlock_spend(tx)
```

#### Limitations

- Only **C2** (HASHLOCK) outputs are supported. C3 (timelock + hashlock) and C4 (hashlock + expiry + refund) outputs are not.
- The owner script must be **P2PKH or P2WPKH**. P2SH and P2WSH owners are refused with `InvalidHashlockUTXOError`.
- The library cannot validate the transaction against the node's consensus rules. Before sending a real amount, check it with `rpc.test_mempool_accept(raw_tx)` or try a small amount first.

---

## TMSG (Tencoin Message)

**TMSG** encrypts messages, files and whole folders to one or many public keys, so that only the holders of the matching private keys can read them. It works **off-chain** (a payload you store or send yourself) and **on-chain** (the payload sits in an `OP_RETURN` output of a normal transaction, next to a payment to the recipient).

```python
from tencoinlib import tmsg
```

### Overview

| Version | Recipient keys | Who can decrypt | Overhead added to the plaintext |
|---|---|---|---|
| `0x01` | exactly 1 | the owner of that key | 66 bytes |
| `0x02` | 2 – 255 | **any one** of the owners | 34 + 93 × N bytes |

The version is chosen automatically: one key gives version 1, two or more give version 2.

- **Crypto**: ECDH on secp256k1 with a fresh ephemeral key, then AES-256-GCM. The AES key is `SHA-256(compressed ephemeral_priv × recipient_pub)`. Version 2 encrypts the data once with a random content key and wraps that key for every recipient.
- **Payload layout**: `"TMSG"` · version · (v2: N, then N × 93-byte recipient blocks) · ephemeral key (v1) · nonce · ciphertext + 16-byte tag. It is byte-for-byte compatible with the reference `enc_file.py` / `dec_file.py` tools.
- **Authenticity**: TMSG proves that nothing was modified, not who wrote it. Anyone who knows your public key can encrypt to you. If the sender must be provable, sign the plaintext too (see [Message Signing](#message-signing)).
- **Recipients are visible**: the number of recipients and their ephemeral keys can be seen in a v2 payload (not who they are).
- Keys can be given as bytes (33 or 65), hex (a `0x` prefix is accepted), several keys in one string (separated by space, comma or semicolon), or an **address** (see below; needs `rpc=`). Duplicates are dropped.

### Getting a recipient's public key

An address is only a hash of a key, so you need the key itself. Three ways:

1. **They give it to you.** With a wallet: `wallet.tmsg_public_key("p2wpkh")` (hex, 66 chars) for the `tc1q...` address, or `"p2pkh"` for the `T...` address.
2. **Look it up on-chain with `getpublickey`.** `rpc.get_public_key(address)` finds the key the address revealed when it spent an output. It only works for addresses that have **already spent** (see [Get Public Key](#get-public-key-getpublickey)).
3. **Pass the address directly**: `tmsg.encrypt(data, "tc1q...", rpc=rpc)` runs the lookup for you.

### Off-chain: messages

```python
from tencoinlib import tmsg

recipient = "02ab...66 hex chars..."                  # or a list of keys

# Text -> payload (bytes, or hex with as_hex=True)
payload = tmsg.encrypt_text("Hello Alice", recipient)
hex_payload = tmsg.encrypt_text("Hello Alice", recipient, as_hex=True)

# Payload (bytes or hex) -> text
text = tmsg.decrypt_text(hex_payload, private_key)    # 32 bytes or 64 hex chars

# Raw bytes
payload = tmsg.encrypt(b"\x00\x01 binary", [pub_alice, pub_bob])    # v2: Alice OR Bob can open it
data = tmsg.decrypt(payload, bob_private_key)

# Look inside without a key
info = tmsg.inspect(payload)
print(info.version, info.recipients, info.plaintext_size, info.overhead)
```

`decrypt()` also accepts a list of private keys and tries them in order.

### Off-chain: files and folders

```python
# One file:   report.pdf  ->  report.pdf.enc
res = tmsg.encrypt_file("report.pdf", [pub_alice, pub_bob])
print(res.path, res.version, res.recipients)
tmsg.decrypt_file("report.pdf.enc", private_key)           # -> report.pdf

# A folder, as ONE encrypted archive (names and structure hidden): docs/ -> docs.zip.enc
tmsg.encrypt_folder("docs", pub_alice)
tmsg.decrypt_folder("docs.zip.enc", private_key)           # extracts into docs_dec/

# A folder, file by file (names visible): docs/ -> docs_enc/  with .enc on every file
tmsg.encrypt_folder("docs", pub_alice, mode="files")
tmsg.decrypt_folder("docs_enc", private_key)               # -> docs_enc_dec/

# An existing .zip is accepted as input too
tmsg.encrypt_folder("pack.zip", pub_alice)
```

| Behaviour | Details |
|---|---|
| Existing files | Never overwritten: a numbered name (`name_1.ext`) is used, or pass `overwrite=True`. With an explicit `output=` an existing file raises `FileExistsError`. |
| Writes | Atomic (temp file, then rename); a failed decryption writes nothing. |
| Size | Each file is processed in memory as one AEAD message: limit `max_size` (default 1 GiB). |
| Results | `FileResult` (`path`, `input_size`, `output_size`, `version`, `recipients`) and `FolderResult` (`output`, `files`, `errors`, `skipped`, `ok`). |
| Symlinks | Skipped when encrypting a folder (listed in `result.skipped`). |
| Errors per file | In `"files"` mode a failing file does not stop the others; check `result.errors`. |

**Hostile archives.** Anyone can encrypt to your public key, so decrypting a folder never trusts the archive: entries with absolute paths, `..`, drive letters, links or special files are skipped (and listed in `result.skipped`), and the amount written is bounded by `max_extract_size` (default 4 GiB) and `max_files` (default 100 000) — raising `TMSGSizeError` when exceeded.

### On-chain messages

An on-chain TMSG is a normal transaction with this layout:

| Output | Content |
|---|---|
| 0 | **At least 1 Teno** to the recipient address. The dust limit does **not** apply to transactions that carry a TMSG. |
| 1 | `OP_RETURN` holding the encrypted payload (up to 1024 data bytes) |
| 2 | Change back to the sender (only if something is left) |

**Capacity.** An `OP_RETURN` carries 1024 bytes, so a message can be up to **958 bytes** for one recipient (1024 − 66). With N recipients the maximum is `1024 − (34 + 93 × N)`:

| Recipients | 1 (v1) | 2 | 3 | 5 | 10 |
|---|---|---|---|---|---|
| Max message size | 958 | 804 | 711 | 525 | 60 |

Use `tmsg.max_plaintext(recipients)` to get the number.

#### With a wallet (simplest)

```python
from tencoinlib import Wallet
from tencoinlib.rpc import RPCClient

rpc = RPCClient(host="127.0.0.1", port=10111, token="your-token")
wallet = Wallet.load("my_wallet.tcw")

with wallet.unlocked(password):
    tx = wallet.send_tmsg(
        rpc,
        to_address="tc1q...",          # gets 1 Teno (raise it with amount=...)
        message="Meeting at 10:00",
        # recipients=None  -> the recipient's key is looked up on-chain with getpublickey
        # recipients="02ab..." or ["02ab...", "03cd..."] -> explicit keys (v2 for several)
        include_self=True,             # optional: you can read your own message later
    )

print(tx.txid, tx.fee, tx.version)
rpc.send_raw_transaction(tx.raw_transaction)      # or pass broadcast=True above
```

`send_tmsg()` takes the UTXOs of the wallet's addresses from `rpc` (or from `utxos=[...]`), spends the fewest and largest ones that cover the cost, sends the change to `change_address` (default: the wallet's P2PKH address), signs, and returns a signed `TMSGTransaction`. It never broadcasts unless you pass `broadcast=True`. For keys beyond index 0 pass `account`, `change`, `index`.

#### Step by step (no wallet)

```python
from tencoinlib import tmsg

utxos = rpc.list_unspent(sender_address)          # dicts with txid, vout, amount, scriptPubKey

tx = tmsg.build_tmsg_transaction(
    utxos,
    "tc1q...recipient",
    "Meeting at 10:00",
    recipients="02ab...",                         # or None + rpc=rpc to look it up
    amount=1,                                     # Tenos for the recipient (default and minimum 1)
    change_address=sender_address,                # required if more than dust would be left over
    fee_rate=None,                                # Tenos per vbyte; or fee=... for an exact fee
    rpc=rpc,
)

tx.sign([sender_private_key])                     # a pool: every input uses the key that matches it
rpc.test_mempool_accept(tx.raw_transaction)       # optional dry run
txid = rpc.send_raw_transaction(tx.raw_transaction)
```

`TMSGTransaction` fields: `tx` (the `Transaction`), `payload`, `recipients`, `version`, `fee`, `amount`, `change`, `plaintext_size`, `padding`, `signed`, `txid`, and `raw_transaction` (only after `sign()`). Inputs must be P2WPKH or P2PKH outputs.

**Fees.** The estimate is `max(vsize × fee_rate, MIN_RELAY_FEE)` and already includes the signatures and the OP_RETURN (default rate: `FeeCalculator.DEFAULT_FEE_RATE`). If your node demands more for data-carrying transactions, pass `fee_rate=` or an exact `fee=`, and check with `rpc.test_mempool_accept()` first.

**Change.** If at least `DUST_LIMIT` would be left over and no `change_address` is given, the build is refused instead of burning the rest as fee. A remainder below the dust limit goes to the miner.

**Unsafe message sizes.** A script length of 193–207 bytes is indistinguishable from a conditional-output flag byte (`0xC1`–`0xCF`) when an output is parsed, so such an `OP_RETURN` must never be produced. For one recipient this affects text messages of **124–138 bytes**. By default `build_tmsg_transaction()` raises `TMSGSizeError` (with `.pad_bytes`, the number of bytes to add). For text messages you can pass `size_policy="pad"` to append the needed spaces (at most 15):

```python
tx = tmsg.build_tmsg_transaction(utxos, to, text, recipients=pub, change_address=addr,
                                 size_policy="pad")
print(tx.padding)        # spaces that were appended
```

`TransactionBuilder.op_return()` applies the same check to every `OP_RETURN` output.

#### Reading an on-chain message

```python
# By txid (needs rpc), raw hex, or a Transaction object
for msg in tmsg.decrypt_transaction("67d70f82...", private_key, rpc=rpc):
    print(msg.output_index, msg.text)         # msg.plaintext for raw bytes

# Only look for TMSG payloads (no key needed)
for item in tmsg.extract_tmsg_payloads(raw_hex):
    print(item.output_index, tmsg.inspect(item.payload))

# With a wallet: tries the canonical, BIP-84 and BIP-44 keys
with wallet.unlocked(password):
    messages = wallet.decrypt_tmsg_transaction(txid, rpc=rpc)
    data = wallet.decrypt_tmsg(payload_hex)                    # a bare payload
```

An output counts as a TMSG when its script is `OP_RETURN <one push>` and the data starts with `TMSG`. `decrypt_transaction()` raises `TMSGFormatError` if the transaction carries none, and `TMSGDecryptionError` if it carries some but none of your keys opens them.

### TMSG and the OP_RETURN limit

`TransactionBuilder.op_return()` now accepts up to **1024** bytes (it was 80) and encodes large payloads with `OP_PUSHDATA2`, exactly as the node expects. Use `add_tmsg_output(address, payload, amount=1)` to add the first two outputs of a TMSG transaction by hand.

---

## Complete Examples

### Example 1: Complete Wallet Setup

```python
from tencoinlib import Wallet, WalletAuthError
from tencoinlib.rpc import RPCClient
from tencoinlib.constants import TENOS_PER_TEC
import os

WALLET_FILE = "my_wallet.tcw"

# Create a new wallet or load an existing one
if not os.path.exists(WALLET_FILE):
    wallet = Wallet.create()
    print(f"\n⚠️  IMPORTANT: Save this mnemonic phrase safely!")
    print(f"Mnemonic: {wallet.get_mnemonic()}\n")
    password = input("Set a wallet password: ")
    wallet.save(WALLET_FILE, password=password)
    print(f"Wallet saved to {WALLET_FILE}")
else:
    password = input("Enter wallet password: ")
    try:
        wallet = Wallet.load(WALLET_FILE).unlock(password)
    except WalletAuthError:
        print("Wrong password!")
        exit(1)

# Connect to node
rpc = RPCClient(host="127.0.0.1", port=10111, token="your-token")

# Get balance
address = wallet.get_address()
balance_tenos = rpc.get_balance(address)
balance_tec   = balance_tenos / TENOS_PER_TEC

print(f"\nWallet Information:")
print(f"Address: {address}")
print(f"Balance: {balance_tec:.8f} TEC ({balance_tenos} Tenos)")

# Show UTXOs
utxos = rpc.list_unspent(address)
print(f"\nUnspent Outputs: {len(utxos)}")
for utxo in utxos:
    print(f"  {utxo['amount']} Tenos from {utxo['txid'][:16]}...")

# Lock when done
wallet.lock()
```

### Example 2: Complete Send Transaction

```python
from tencoinlib import Wallet, TransactionBuilder, TransactionSigner, WalletAuthError
from tencoinlib.rpc import RPCClient
from tencoinlib.constants import TENOS_PER_TEC
from tencoinlib.transaction.address import address_to_script

# Load and unlock wallet
password = input("Wallet password: ")
try:
    wallet = Wallet.load("my_wallet.tcw").unlock(password)
except WalletAuthError:
    print("Wrong password!")
    exit(1)

rpc = RPCClient(host="127.0.0.1", port=10111, token="your-token")
sender_address = wallet.get_address()

# Get recipient address and amount
recipient_address = input("Recipient address: ")
amount_tec = float(input("Amount (TEC): "))
amount_tenos = int(amount_tec * TENOS_PER_TEC)

# Get UTXOs
utxos = rpc.list_unspent(sender_address)
if not utxos:
    print("No UTXOs available!")
    exit(1)

# Calculate total available
total_available = sum(u["amount"] for u in utxos)
print(f"\nAvailable: {total_available / TENOS_PER_TEC:.8f} TEC")

# Build transaction
builder = TransactionBuilder()

# Add all UTXOs
for utxo in utxos:
    builder.add_input(
        txid=utxo["txid"],
        vout=utxo["vout"],
        value=utxo["amount"],
        script_pubkey=bytes.fromhex(utxo["scriptPubKey"])
    )

# Add output (supports SegWit, P2PKH, or P2SH addresses)
builder.add_output(recipient_address, amount_tenos)

# Set change address
builder.set_change_address(sender_address)

# Set fee rate
builder.set_fee_rate(20)

# Get summary
summary = builder.get_summary()
print(f"\nTransaction Summary:")
print(f"  Inputs: {summary['inputs_count']}")
print(f"  Outputs: {summary['outputs_count']}")
print(f"  Total Input: {summary['total_input'] / TENOS_PER_TEC:.8f} TEC")
print(f"  Total Output: {summary['total_output'] / TENOS_PER_TEC:.8f} TEC")
print(f"  Estimated Fee: {summary['fee'] / TENOS_PER_TEC:.8f} TEC")

# Check sufficient funds
total_needed = amount_tenos + summary['fee']
if total_available < total_needed:
    print(f"\n❌ Insufficient funds!")
    print(f"  Need: {total_needed / TENOS_PER_TEC:.8f} TEC")
    print(f"  Have: {total_available / TENOS_PER_TEC:.8f} TEC")
    exit(1)

# Build transaction
tx, actual_fee = builder.build()
print(f"\n  Actual Fee: {actual_fee / TENOS_PER_TEC:.8f} TEC")
if summary['has_change']:
    print(f"  Change: {summary['change_amount'] / TENOS_PER_TEC:.8f} TEC")

# Prepare for signing
utxo_data = []
private_keys = []

for utxo in utxos:
    utxo_data.append({
        "value": utxo["amount"],
        "script_pubkey": bytes.fromhex(utxo["scriptPubKey"]),
        "address": sender_address  # TransactionSigner detects address type automatically
    })
    private_keys.append(bytes.fromhex(wallet.get_private_key_hex()))

# Sign transaction (supports SegWit, P2PKH, and P2SH automatically)
print("\nSigning transaction...")
signed_tx = TransactionSigner.sign_transaction(tx, utxo_data, private_keys)

# Verify
print(f"Transaction ID: {signed_tx.txid()}")
print(f"Size: {signed_tx.calculate_size()} bytes")
print(f"Virtual Size: {signed_tx.calculate_vsize()} bytes")

# Confirm before sending
confirm = input("\nSend transaction? (yes/no): ")
if confirm.lower() != "yes":
    print("Transaction cancelled")
    exit(0)

# Broadcast
print("\nBroadcasting transaction...")
tx_hex = signed_tx.serialize().hex()
txid = rpc.send_raw_transaction(tx_hex)

print(f"\n✅ Transaction sent successfully!")
print(f"TXID: {txid}")
print(f"View on block explorer: https://explorer.tencoin.org/tx/{txid}")
```

### Example 3: Transaction History

```python
from tencoinlib.rpc import RPCClient
from tencoinlib.constants import TENOS_PER_TEC

rpc = RPCClient(host="127.0.0.1", port=10111, token="your-token")
address = "tc1q..."

# Get UTXOs (received transactions)
utxos = rpc.list_unspent(address)

print(f"Transaction History for {address}\n")
print(f"Unspent Outputs: {len(utxos)}\n")

for i, utxo in enumerate(utxos, 1):
    tx_info = rpc.get_transaction(utxo["txid"])
    
    print(f"Transaction {i}:")
    print(f"  TXID: {utxo['txid']}")
    print(f"  Amount: {utxo['amount'] / TENOS_PER_TEC:.8f} TEC")
    print(f"  Confirmations: {utxo.get('confirmations', 0)}")
    print(f"  Block Height: {tx_info.get('blockheight', 'Pending')}")
    print("---")
```

### Example 4: Multi-Address Wallet

```python
from tencoinlib import Wallet

wallet = Wallet.recover("your mnemonic phrase")

# Generate receiving addresses
print("Receiving Addresses:")
for i in range(10):
    priv, addr = wallet.derive_address(account=0, change=0, index=i)
    print(f"  {i:2d}: {addr}")

print("\nChange Addresses:")
for i in range(5):
    priv, addr = wallet.derive_address(account=0, change=1, index=i)
    print(f"  {i:2d}: {addr}")

# Get next unused address
priv, next_addr = wallet.get_next_address(change=0)
print(f"\nNext Receiving Address: {next_addr}")
```

---

## API Reference

### Wallet Class

#### Class Methods

**`Wallet.create(strength: int = 128) -> Wallet`**
- Create a new HD wallet from a freshly generated BIP-39 mnemonic
- **Parameters**: `strength` - Entropy strength in bits (128, 160, 192, 224, 256)
- **Returns**: New `Wallet` instance (UNLOCKED)

**`Wallet.recover(mnemonic: str, passphrase: str = "") -> Wallet`**
- Recover wallet from mnemonic phrase
- **Parameters**:
  - `mnemonic` - BIP-39 mnemonic phrase
  - `passphrase` - Optional BIP-39 passphrase
- **Returns**: Recovered `Wallet` instance (UNLOCKED)
- **Raises**: `WalletError` if mnemonic is invalid

**`Wallet.from_xpub(xpub: str) -> Wallet`**
- Create a watch-only wallet from a master/account xpub
- Can derive addresses via `derive_address_from_xpub`, but has no access to private keys or seed

**`Wallet.from_xprv(xprv: str) -> Wallet`**
- Create a wallet from a master/account xprv
- Full private derivation is available, but no mnemonic/seed is required

**`Wallet.from_private_key(private_key: Union[bytes, str]) -> Wallet`**
- Create a wallet from a single raw 32-byte private key (bytes, or a 64-char hex string) — no mnemonic, no seed, and no BIP-32 chain code
- Canonical address is legacy P2PKH; distinct from `from_xprv()`, which carries a chain code and can derive a full tree
- **Returns**: `Wallet` instance (UNLOCKED), `wallet_type == "privkey"`
- **Raises**: `WalletError` if the key is not exactly 32 bytes
- Operations requiring a chain code (`get_master_xprv`/`xpub`, `derive_xprv`/`xpub`, `get_account_xprv`/`xpub`, `get_address("p2wpkh")`/`get_address("p2sh")`) raise `WalletError` on this wallet type

**`Wallet.load(filepath: str) -> Wallet`**
- Read a `.tcw` file header without decrypting — returns a LOCKED wallet
- **Parameters**: `filepath` - Path to a `.tcw` file
- **Returns**: LOCKED `Wallet` instance
- **Raises**: `TCWFormatError` if file is invalid, `TCWVersionError` if version unsupported, `FileNotFoundError`

**`Wallet.load_from_file(filepath: str, password: str) -> Wallet`**
- Convenience method: load and fully decrypt in one call
- Equivalent to `Wallet.load(filepath).unlock(password)`
- **Returns**: UNLOCKED `Wallet` instance

#### Lock / Unlock

**`wallet.unlock(password: str) -> Wallet`**
- Decrypt the wallet's `.tcw` file and load secrets into RAM
- **Returns**: self (UNLOCKED) — supports chaining: `Wallet.load(path).unlock(pw)`
- **Raises**: `WalletAuthError` if password is wrong or file is corrupted, `WalletError` if no `.tcw` file is associated

**`wallet.lock() -> None`**
- Discard all secret material from RAM; set state to LOCKED
- Public metadata (address, xpub, indices) is preserved

**`wallet.unlocked(password: str) -> ContextManager`**
- Context manager: unlock on enter, lock on exit (even if an exception occurs)
- Usage: `with wallet.unlocked("pw") as w: ...`

**`wallet.is_locked -> bool`** *(property)*
- `True` when no secret material is held in RAM

#### Persistence

**`wallet.save(filepath: str, password: str) -> None`**
- Encrypt and write wallet to a TCW v1 binary file
- Wallet must be UNLOCKED; password must be at least 8 characters
- **Raises**: `WalletLockedError`, `ValueError` if password too short

**`wallet.save_to_file(filepath: str, password: str) -> None`**
- Alias for `save()`

#### Instance Methods

**`get_address(type: str = "p2wpkh", script: Optional[bytes] = None) -> str`**
- Get address for the current key in the requested form
- `p2wpkh` is available while LOCKED; `p2pkh` and `p2sh` require UNLOCKED
- **Parameters**:
  - `type`: One of `"p2wpkh"` (default, BIP-84), `"p2pkh"` (BIP-44), `"p2sh"` (BIP-49 nested SegWit / P2SH-P2WPKH), `"p2wsh"`
  - `script`: For `"p2sh"` (optional) or `"p2wsh"` (required)
- **Returns**: Address string (`tc1q...`, `T...`, or `M...`)
- **Raises**: `WalletError` for any type other than `"p2pkh"` on a `"privkey"`-type wallet (no chain code to derive from)

**`get_private_key_hex() -> str`**
- Get private key as hex string (UNLOCKED required)
- **Raises**: `WalletLockedError`, `WalletError` in watch-only wallets

**`get_public_key_hex() -> str`**
- Get public key as hex string (compressed); available while LOCKED

**`get_mnemonic() -> str`**
- Get mnemonic phrase (UNLOCKED required)
- **Raises**: `WalletLockedError`, `WalletError` if wallet has no mnemonic

**`get_master_xprv() -> str`**
- Get master xprv as Base58Check string (UNLOCKED required, non-watch-only only)

**`get_master_xpub() -> str`**
- Get master xpub as Base58Check string

**`derive_xprv(path: str) -> str`**
- Derive extended private key at a BIP-32 path (UNLOCKED required, non-watch-only only)

**`derive_xpub(path: str) -> str`**
- Derive extended public key at a BIP-32 path
- Full wallets support hardened + non-hardened; watch-only: non-hardened only

**`get_account_xprv(account: int, purpose: int = 84) -> str`**
- Get account-level xprv at `m/{purpose}'/5353'/account'` (UNLOCKED required)
- `purpose` defaults to 84 (native SegWit) for backward compatibility; pass `44` or `49` explicitly for the legacy P2PKH or nested-SegWit branch

**`get_account_xpub(account: int, purpose: int = 84) -> str`**
- Get account-level xpub at `m/{purpose}'/5353'/account'`
- Same `purpose` default/override behavior as `get_account_xprv`

**`get_account_xprv_p2pkh(account: int = 0) -> str`**  
**`get_account_xpub_p2pkh(account: int = 0) -> str`**
- BIP-44 account-level xprv/xpub at `m/44'/5353'/account'`

**`get_account_xprv_p2sh_segwit(account: int = 0) -> str`**  
**`get_account_xpub_p2sh_segwit(account: int = 0) -> str`**
- BIP-49 account-level xprv/xpub at `m/49'/5353'/account'`

**`derive_address(account: int = 0, change: int = 0, index: int = 0) -> Tuple[str, str]`**
- Derive BIP-84 address at a specific path (UNLOCKED required)
- **Returns**: `(private_key_hex, address)`

**`get_next_address(change: int = 0) -> Tuple[str, str]`**
- Increment address index and return the next address (UNLOCKED required)
- **Returns**: `(private_key_hex, address)`

**`derive_address_from_xpub(change: int, index: int) -> str`**
- Derive address from the wallet's base xpub; watch-only safe

**`export_xpub(path: str) -> str`**  
**`export_xprv(path: str) -> str`**  
**`import_xpub(xpub: str) -> None`**  
**`import_xprv(xprv: str) -> None`**
- BIP-32 import/export helpers; xprv operations require UNLOCKED

**`wallet_type -> str`** *(property)*
- One of `"hd"`, `"xpub"`, `"xprv"`, `"privkey"`

#### HASHLOCK Spending

**`sign_hashlock_spend(tx: Transaction, input_index: int, utxo: dict, secret: Union[str, bytes], *, account: int = 0, change: int = 0, index: int = 0) -> Transaction`**
- Sign input `input_index` of `tx` as a HASHLOCK (C2) spend (UNLOCKED required)
- Verifies the secret against the UTXO's `secret_hash`, finds the wallet key that owns the UTXO, signs, and places `[sig, pubkey, preimage]` in the witness (P2WPKH owner) or `<sig> <pubkey> <preimage>` in the scriptSig (P2PKH owner)
- **Parameters**:
  - `tx` — unsigned transaction (e.g. from `build_hashlock_spend()`); modified in place
  - `input_index` — the input that spends the HASHLOCK UTXO
  - `utxo` — dict with `txid`, `vout`, `value`, `script_pubkey`, `secret_hash`
  - `secret` — TCS / free-form text (`str`) or raw preimage (`bytes`)
  - `account`, `change`, `index` — HD position of the owning key (seed wallets)
- **Returns**: The same `Transaction`
- **Raises**: `WalletLockedError`, `WalletError` (watch-only), `InvalidHashlockUTXOError`, `InvalidHashlockSecretError`, `HashlockSpendSigningError` (no wallet key owns the UTXO, outpoint mismatch)

**`spend_hashlock(utxo: dict, destination: str, amount: int = None, fee: int = None, secret: Union[str, bytes] = None, *, fee_rate: int = None, change_address: str = None, account: int = 0, change: int = 0, index: int = 0) -> HashlockSpendResult`**
- Spend a HASHLOCK UTXO end to end (UNLOCKED required): validate → verify secret → build → sign → finalize
- **Parameters**: `amount=None` sweeps the whole UTXO; `fee=None` estimates the fee from `fee_rate`; `change_address` is required when `amount` leaves at least `DUST_LIMIT` behind; `secret` is required
- **Returns**: `HashlockSpendResult` (`tx`, `raw_transaction`, `txid`, `fee`, `amount`, `change`, `secret_hash`)
- **Raises**: same as `sign_hashlock_spend()`, plus `HashlockSpendBuildError`

#### TMSG

**`tmsg_public_key(address_type: str = "p2wpkh", account: int = 0, change: int = 0, index: int = 0) -> str`**
- Compressed public key (66 hex chars) that others encrypt TMSG messages to (UNLOCKED required)
- `"p2wpkh"` is the key of the `tc1q...` address (BIP-84, seed wallets only), `"p2pkh"` the key of the `T...` address (BIP-44, or the raw key of a private-key wallet)

**`send_tmsg(rpc, to_address: str, message: Union[str, bytes], recipients=None, *, amount: int = 1, fee: int = None, fee_rate: int = None, change_address: str = None, include_self: bool = False, size_policy: str = "error", utxos: List[dict] = None, broadcast: bool = False, account: int = 0, change: int = 0, index: int = 0) -> TMSGTransaction`**
- Send an encrypted on-chain message (UNLOCKED required): output 0 pays `amount` Tenos to `to_address`, output 1 is the `OP_RETURN` with the TMSG, output 2 the change
- **Parameters**:
  - `recipients` — public key(s) allowed to decrypt; `None` looks up the key of `to_address` with `rpc.get_public_key()`
  - `include_self` — also encrypt to this wallet (makes it a v2 message)
  - `change_address` — default: the wallet's P2PKH address
  - `utxos` — use these instead of asking `rpc` (dicts with `txid`, `vout`, `amount`, `scriptPubKey`)
  - `size_policy` — `"error"` or `"pad"` (see [On-chain messages](#on-chain-messages))
  - `broadcast` — also send it with `rpc.send_raw_transaction` (`tx.broadcast_txid` is then set)
- **Returns**: signed `TMSGTransaction`
- **Raises**: `WalletLockedError`, `WalletError` (watch-only, no UTXOs), `TMSGError`, `TMSGSizeError`, `TMSGKeyError`, `PublicKeyNotFoundError`

**`decrypt_tmsg(payload: Union[bytes, str], *, account: int = 0, change: int = 0, index: int = 0) -> bytes`**
- Decrypt a bare TMSG payload (bytes or hex) with the wallet's keys (canonical, BIP-84 and BIP-44 at `account`/`change`/`index`)
- **Raises**: `TMSGDecryptionError`, `TMSGFormatError`

**`decrypt_tmsg_transaction(source, *, rpc=None, account: int = 0, change: int = 0, index: int = 0) -> List[DecryptedMessage]`**
- Decrypt the TMSG(s) in a transaction (`Transaction`, raw hex, or txid with `rpc`)

#### ESP32 Bridge

**`export_to_esp_blob(esp_password: str, iterations: int = 10000, totp: List[str] = None, totp_mask: int = None, passphrase_used: bool = None) -> bytes`**
- Encrypt this wallet's secrets as a TCE1 blob for an ESP32 device (UNLOCKED required)
- Only `"hd"` and `"privkey"` wallets can be exported
- **Raises**: `WalletLockedError`, `ESPBridgeError` (no ESP equivalent for `"xprv"`/`"xpub"`), `TCEFormatError` (iterations out of range)

**`Wallet.import_from_esp_blob(blob: bytes, esp_password: str) -> Wallet`**
- Decrypt a TCE1 blob and build an UNLOCKED wallet directly from it
- **Returns**: `Wallet` instance, `wallet_type` `"hd"` or `"privkey"`
- **Raises**: `TCEAuthError` (wrong password/corrupted), `TCEFormatError`, `ESPBridgeError` (inconsistent payload)

A TCE1 blob saved to disk uses the **`.tce`** extension (paralleling `.tcw`). `wallet_storage.tce.save_esp_blob(filepath, blob)` / `load_esp_blob(filepath)` read/write it, with the same extension auto-resolution as `Wallet.load()`. `esp_blob_to_tcw_file()` accepts either raw bytes or a `.tce` path directly; `tcw_file_to_esp_blob()` takes an optional `out_path` to also save a `.tce` copy.

### TransactionBuilder Class

#### Methods

**`add_input(txid: str, vout: int, value: int, script_pubkey: bytes, sequence: int = 0xffffffff) -> TransactionBuilder`**
- Add transaction input (UTXO)
- **Returns**: Self for method chaining
- **Raises**: `TransactionBuilderError` if invalid

**`add_output(address: str, amount: int) -> TransactionBuilder`**
- Add transaction output
- **Returns**: Self for method chaining
- **Raises**: `TransactionBuilderError` if amount below dust limit

**`set_change_address(address: str) -> TransactionBuilder`**
- Set change address
- **Returns**: Self for method chaining

**`set_fee_rate(fee_rate: int) -> TransactionBuilder`**
- Set custom fee rate (Tenos per byte)
- **Returns**: Self for method chaining

**`set_fee(amount: float | int, unit: str = "Teno") -> TransactionBuilder`**
- Set a fixed fee amount (overrides fee rate)
- **Parameters**:
  - `amount` — Fee value; float for TEC, int for Teno
  - `unit` — `"TEC"` (converts × 100_000_000) or `"Teno"` (no conversion); case-insensitive
- **Returns**: Self for method chaining
- **Raises**: `TransactionBuilderError` if unit is unrecognized

**`add_timelock_output(address: str, amount: int, lock_height: int = None, lock_timestamp: int = None) -> TransactionBuilder`**
- Add an output that is unspendable until a block height or Unix timestamp is reached
- **Parameters**:
  - `address` — Recipient address (any supported type)
  - `amount` — Amount in Tenos
  - `lock_height` — Absolute block height after which the output is spendable
  - `lock_timestamp` — Unix timestamp after which the output is spendable
- Provide exactly one of `lock_height` or `lock_timestamp`
- **Returns**: Self for method chaining
- **Raises**: `TransactionBuilderError` if both or neither lock parameters are given, or if amount is below dust limit

**`add_hashlock_output(address: str, amount: int, preimage: bytes = None, secret_hash: bytes = None) -> TransactionBuilder`**
- Add a HASHLOCK (`0xC2`) output; spending it needs the owner's signature and the preimage (see [HASHLOCK (C2) Outputs](#hashlock-c2-outputs))
- **Parameters**:
  - `address` — Owner address (any valid type; P2PKH/P2WPKH to be spendable with this library)
  - `amount` — Amount in Tenos (at least `DUST_LIMIT`)
  - `preimage` — Raw secret bytes, 1–64 bytes; the builder computes `SHA-256(preimage)`
  - `secret_hash` — Precomputed 32-byte `SHA-256(preimage)`
- Provide exactly one of `preimage` or `secret_hash`
- **Returns**: Self for method chaining
- **Raises**: `TransactionBuilderError` if both or neither are given, the preimage/hash has the wrong size, the amount is below dust, or the address is invalid

**`op_return(data: Union[str, bytes]) -> TransactionBuilder`**
- Add an `OP_RETURN` output (value 0). Strings are UTF-8 encoded
- Maximum **1024** bytes (`OP_RETURN_MAX_DATA`); payloads over 75 bytes use `OP_PUSHDATA1` / `OP_PUSHDATA2`
- A payload of 190–204 bytes is refused: its 193–207 byte script is indistinguishable from a conditional-output flag byte (`0xC1`–`0xCF`)
- **Raises**: `TransactionBuilderError`

**`add_tmsg_output(address: str, payload: bytes, amount: int = 1) -> TransactionBuilder`**
- Add the first two outputs of an on-chain TMSG transaction: `amount` Tenos to `address` (output 0) and an `OP_RETURN` with the TMSG payload (output 1). The change output, if any, becomes output 2
- The dust limit does **not** apply: `amount` may be as low as 1 Teno (`TMSG_MIN_PAYMENT`)
- Must be called on a builder without outputs
- **Parameters**: `payload` — complete TMSG payload (starts with `b"TMSG"`), e.g. from `tmsg.encrypt()`
- **Raises**: `TransactionBuilderError` for an invalid address, a payload that is not a TMSG, an amount below 1, outputs already present, or an unsafe/oversized payload

**`set_segwit(use_segwit: bool) -> TransactionBuilder`**
- Set whether to use SegWit inputs
- **Returns**: Self for method chaining

**`set_locktime(locktime: int) -> TransactionBuilder`**
- Set transaction locktime
- **Returns**: Self for method chaining

**`build() -> Tuple[Transaction, int]`**
- Build the transaction
- **Returns**: `(transaction, actual_fee)`
- **Raises**: `TransactionBuilderError` if build fails

**`build_raw() -> Tuple[str, int]`**
- Build transaction and return raw hex
- **Returns**: `(raw_hex, fee)`

**`get_summary() -> Dict[str, Any]`**
- Get transaction summary

**`calculate_total_input() -> int`**
- Calculate total input amount in Tenos

**`calculate_total_output(include_change: bool = False) -> int`**
- Calculate total output amount in Tenos

**`calculate_fee(include_change: bool = True) -> int`**
- Calculate estimated fee in Tenos

**`calculate_change() -> Tuple[int, bool]`**
- Calculate change amount
- **Returns**: `(change_amount, has_change)`

**`clear() -> TransactionBuilder`**
- Clear all inputs and outputs
- **Returns**: Self for method chaining

**`copy() -> TransactionBuilder`**
- Create a copy of this builder

### TransactionSigner Class

Universal transaction signer that automatically detects address types and uses the appropriate signing method.

#### Static Methods

**`sign_transaction(tx: Transaction, utxos: List[dict], private_keys: Union[List[bytes], List[List[bytes]]]) -> Transaction`**
- Sign a transaction with any combination of address types
- **Parameters**:
  - `tx` - Unsigned transaction
  - `utxos` - List of UTXO dictionaries. Fields by type:
    - All: `address` (str)
    - P2PKH / P2SH: `script_pubkey` (bytes)
    - P2SH: `redeem_script` (bytes, required), `cosigner_keys` (List[bytes], optional)
    - P2WPKH: `value` (int)
    - P2WSH: `value` (int), `witness_script` (bytes, required), `cosigner_keys` (List[bytes], optional)
  - `private_keys` - One entry per input. Three accepted formats:
    - Flat: `[key_a, key_b]` — one key per input (single-sig)
    - Nested: `[[key_a1, key_a2], [key_b1]]` — one list per input (multisig)
    - Mixed: `[key_a, [key_b1, key_b2]]` — any combination
- **Returns**: Signed transaction
- **Raises**: `SigningError` if signing fails or fewer keys than required m are provided
- **Supported Address Types**: P2WPKH, P2WSH, P2PKH, P2SH (single-sig and multisig)

### LegacySigner Class

Legacy transaction signer for P2PKH and P2SH addresses.

#### Static Methods

**`sign_transaction(tx: Transaction, utxos: List[dict], private_keys: Union[List[bytes], List[List[bytes]]]) -> Transaction`**
- Sign a complete transaction with Legacy inputs (P2PKH or P2SH, single-sig or multisig)
- **Parameters**:
  - `tx` - Unsigned transaction
  - `utxos` - List of UTXO dictionaries with `address`, `script_pubkey`, and optionally `redeem_script` and `cosigner_keys`
  - `private_keys` - Flat, nested, or mixed list of keys (same format as `TransactionSigner`)
- **Returns**: Signed transaction
- **Raises**: `SigningError` if signing fails

**`sign_p2pkh_input(tx: Transaction, input_index: int, private_key: bytes, script_pubkey: bytes, sighash_type: int = 1)`**
- Sign a P2PKH input. Produces `scriptSig = <sig> <pubkey>`.
- **Parameters**:
  - `tx` - Transaction (modified in place)
  - `input_index` - Input index to sign
  - `private_key` - 32-byte private key
  - `script_pubkey` - ScriptPubKey of the UTXO
  - `sighash_type` - SIGHASH type (default: SIGHASH_ALL = 1)

**`sign_p2sh_input(tx: Transaction, input_index: int, keys_for_input: List[bytes], redeem_script: bytes, script_pubkey: bytes, sighash_type: int = 1)`**
- Unified P2SH input signer — auto-detects single-sig vs multisig from the redeem script.
- For single-sig: `scriptSig = <sig> <pubkey> <redeem_script>`
- For multisig: `scriptSig = OP_0 <sig1> ... <sigM> <redeem_script>`
- **Parameters**:
  - `tx` - Transaction (modified in place)
  - `input_index` - Input index to sign
  - `keys_for_input` - All available private keys for this input
  - `redeem_script` - Redeem script bytes
  - `script_pubkey` - ScriptPubKey of the UTXO
  - `sighash_type` - SIGHASH type (default: SIGHASH_ALL = 1)

**`sign_p2sh_multisig_input(tx: Transaction, input_index: int, private_keys_for_input: List[bytes], redeem_script: bytes, sighash_type: int = 1)`**
- Sign a P2SH multisig input (BIP-11). Produces `OP_0 <sig1> ... <sigM> <redeem_script>`.
- `private_keys_for_input` must contain at least M keys that match pubkeys in the redeem script.

**`legacy_digest(tx: Transaction, input_index: int, script_code: bytes, sighash_type: int = 1) -> bytes`**
- Calculate legacy transaction digest (pre-SegWit SIGHASH_ALL)
- **Returns**: 32-byte digest

### SegWitSigner Class

SegWit transaction signer (BIP-143) for P2WPKH addresses.

#### Static Methods

**`sign_transaction(tx: Transaction, utxos: List[dict], private_keys: Union[List[bytes], List[List[bytes]]]) -> Transaction`**
- Sign a complete transaction with SegWit inputs (P2WPKH or P2WSH)
- **Parameters**:
  - `tx` - Unsigned transaction
  - `utxos` - List of UTXO dictionaries. P2WSH inputs must include `witness_script`; multisig inputs may also include `cosigner_keys`.
  - `private_keys` - Flat, nested, or mixed list of keys (same format as `TransactionSigner`)
- **Returns**: Signed transaction
- **Raises**: `SigningError` if signing fails

**`sign_p2wpkh_input(tx: Transaction, input_index: int, utxo: dict, private_key: bytes)`**
- Sign a P2WPKH input. Sets `witness = [sig, pubkey]`.
- **Parameters**:
  - `tx` - Transaction (modified in place)
  - `input_index` - Input index to sign
  - `utxo` - UTXO dict with `value` and `address`
  - `private_key` - 32-byte private key

**`sign_p2wsh_input(tx: Transaction, input_index: int, utxo: dict, keys_for_input: List[bytes])`**
- Sign a P2WSH input (single-sig or multisig).
- For multisig: `witness = [b"", sig1, ..., sigM, witness_script]`
- For single-sig: `witness = [sig, pubkey, witness_script]`
- **Parameters**:
  - `tx` - Transaction (modified in place)
  - `input_index` - Input index to sign
  - `utxo` - UTXO dict with `value`, `address`, `witness_script`, and optionally `cosigner_keys`
  - `keys_for_input` - All available private keys for this input

**`sign_input(tx: Transaction, input_index: int, utxo: dict, private_key: bytes)`**
- Backward-compatible alias for `sign_p2wpkh_input`. Signs a single P2WPKH input.
- **Parameters**:
  - `tx` - Transaction (modified in place)
  - `input_index` - Input index to sign
  - `utxo` - UTXO dictionary
  - `private_key` - 32-byte private key

**`create_witness_signature(tx: Transaction, input_index: int, private_key: bytes, script_code: bytes, value: int, sighash_type: int = 1) -> bytes`**
- Create witness signature for SegWit input
- **Returns**: DER-encoded signature with sighash byte

**`verify_witness(tx: Transaction, input_index: int, public_key: bytes, script_code: bytes, value: int, witness: List[bytes]) -> bool`**
- Verify witness signature

### RPCClient Class

#### Constructor

**`RPCClient(host: str = "127.0.0.1", port: int = 10111, token: str = "", timeout: int = 30, use_ssl: bool = False)`**
- Initialize RPC client
- Tests connection on initialization

#### Wallet Methods

- `get_balance(address: str) -> int`
- `list_unspent(address: str, minconf: int = 1) -> List[Dict]`

#### Transaction Methods

- `send_raw_transaction(tx_hex: str) -> str`
- `test_mempool_accept(tx_hex: str) -> Dict`
- `get_transaction(txid: str) -> Dict`
- `get_raw_transaction(txid: str) -> str`
- `decode_raw_transaction(tx_hex: str) -> Dict`

#### Blockchain Methods

- `get_block_count() -> int`
- `get_best_block_hash() -> str`
- `get_block(block_hash: str = None, height: int = None) -> Dict`
- `get_block_header(block_hash: str) -> Dict`
- `get_blockchain_info() -> Dict`
- `get_mempool_info() -> Dict`
- `get_raw_mempool() -> Dict`

#### Network Methods

- `get_peer_info() -> List[Dict]`
- `get_network_info() -> Dict`

#### Mining Methods

- `get_work() -> Dict`
- `submit_block(block_hex: str) -> Dict`

#### Utility Methods

- `validate_address(address: str) -> Dict`
- `estimate_fee(blocks: int = 6) -> Dict`
- `get_difficulty() -> Dict`
- `get_public_key(address: str) -> PublicKeyInfo` — node command `getpublickey`: the public key an address revealed on-chain, verified against the address. Raises `PublicKeyNotFoundError` if the address never spent, `PublicKeyVerificationError` if the node's key does not match the address

### Script Building Functions

#### build_p2pkh_script

**`build_p2pkh_script(pubkey: bytes) -> bytes`**
- Build P2PKH redeem script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
- **Parameters**: `pubkey` - 33-byte compressed public key
- **Returns**: Redeem script bytes

#### build_multisig_script

**`build_multisig_script(m: int, pubkeys: List[bytes], sort_pubkeys: bool = True) -> bytes`**
- Build m-of-n multisig redeem/witness script (standard form)
- **Parameters**:
  - `m` - Required signatures (1..16)
  - `pubkeys` - List of 33-byte compressed public keys (n = len(pubkeys), 1..16)
  - `sort_pubkeys` - If True, sort pubkeys for canonical form (recommended)
- **Returns**: Script bytes (use with `script_to_p2sh_address` or `script_to_p2wsh_address`)

#### script_to_p2sh_address

**`script_to_p2sh_address(script: bytes, version: int = P2SH_VERSION) -> str`**
- Encode a redeem script as P2SH address (M...)
- **Parameters**:
  - `script` - Redeem script bytes
  - `version` - P2SH version byte (default mainnet 0x32)
- **Returns**: Base58Check P2SH address

#### script_to_p2wsh_address

**`script_to_p2wsh_address(script: bytes, hrp: str = MAINNET_HRP) -> str`**
- Encode a witness script as P2WSH (SegWit v0) address (tc1q... with 32-byte program)
- **Parameters**:
  - `script` - Witness script bytes (e.g. multisig script)
  - `hrp` - Bech32 HRP (default mainnet "tc")
- **Returns**: Bech32 P2WSH address

#### pubkey_to_p2pkh_address

**`pubkey_to_p2pkh_address(pubkey: bytes, version: int = P2PKH_VERSION) -> str`**
- Convert public key to P2PKH address (T...)
- **Parameters**:
  - `pubkey` - 33-byte compressed public key
  - `version` - P2PKH version byte (default mainnet 0x41)
- **Returns**: Base58Check P2PKH address

#### pubkey_to_p2sh_p2pkh_address

**`pubkey_to_p2sh_p2pkh_address(pubkey: bytes, version: int = P2SH_VERSION) -> str`**
- Build P2SH address that pays to a plain P2PKH redeem script (single-sig P2SH, M...)
- Not the address type `wallet.get_address("p2sh")` returns — see `pubkey_to_p2sh_p2wpkh_address` below
- **Parameters**:
  - `pubkey` - 33-byte compressed public key
  - `version` - P2SH version byte (default mainnet 0x32)
- **Returns**: Base58Check P2SH address

#### build_p2wpkh_redeem_script

**`build_p2wpkh_redeem_script(pubkey: bytes) -> bytes`**
- Build the BIP-49 witness-v0 redeem script used to nest a P2WPKH output inside P2SH: `OP_0 <20-byte-hash160(pubkey)>`
- **Parameters**: `pubkey` - 33-byte compressed public key
- **Returns**: 22-byte redeem script

#### pubkey_to_p2sh_p2wpkh_address

**`pubkey_to_p2sh_p2wpkh_address(pubkey: bytes, version: int = P2SH_VERSION) -> str`**
- Build a standard BIP-49 nested SegWit address (single-sig P2SH-P2WPKH, M...) — this is what `wallet.get_address("p2sh")` returns
- **Parameters**:
  - `pubkey` - 33-byte compressed public key
  - `version` - P2SH version byte (default mainnet 0x32)
- **Returns**: Base58Check P2SH address

#### Wallet.build_multisig_script (Static Method)

**`Wallet.build_multisig_script(m: int, pubkeys: List[Union[bytes, str]], sort_pubkeys: bool = True) -> bytes`**
- Build standard m-of-n multisig redeem/witness script (convenience method)
- **Parameters**:
  - `m` - Required signatures (1..16)
  - `pubkeys` - List of 33-byte compressed public keys (bytes or hex strings)
  - `sort_pubkeys` - If True, sort pubkeys for canonical form (recommended)
- **Returns**: Script bytes to pass to `get_address("p2sh", script=...)` or `get_address("p2wsh", script=...)`

### Message Signing Module

#### sign_message

**`sign_message(private_key: bytes, message: str) -> str`**
- Sign an arbitrary message with a secp256k1 private key.
- **Parameters**:
  - `private_key` — 32-byte raw private key
  - `message` — UTF-8 message string
- **Returns**: Base64-encoded 65-byte recoverable signature
- **Raises**: `MessageSigningError` if `coincurve` is unavailable or signing fails

#### verify_message

**`verify_message(address: str, message: str, signature_b64: str) -> bool`**
- Verify that a signature was produced by the owner of the given P2PKH address.
- Recovers the public key from the signature and compares the derived address.
- Supports both compressed (31–34) and uncompressed (27–30) recovery bytes.
- **Parameters**:
  - `address` — Tencoin P2PKH address (`T...`)
  - `message` — Original UTF-8 message string
  - `signature_b64` — Base64-encoded signature from `sign_message()`
- **Returns**: `True` if valid, `False` if the signature does not match the address
- **Raises**: `MessageSigningError` for malformed input (invalid Base64, wrong length, bad recovery byte)

#### recover_address_from_signature

**`recover_address_from_signature(message: str, signature_b64: str) -> Optional[str]`**
- Recover the P2PKH address of the signer without knowing it in advance.
- **Parameters**:
  - `message` — Original UTF-8 message string
  - `signature_b64` — Base64-encoded signature from `sign_message()`
- **Returns**: Tencoin P2PKH address string, or `None` if recovery fails
- **Raises**: `MessageSigningError` if `coincurve` is unavailable

#### MessageSigningError

**`class MessageSigningError(Exception)`**
- Raised for all message signing and verification errors, including missing dependencies, malformed input, and cryptographic failures.

### Hashlock Module

```python
from tencoinlib import (
    prepare_hashlock_secret, verify_hashlock_secret, build_hashlock_spend,
    sign_hashlock_input, finalize_hashlock_spend, spend_hashlock,
)
from tencoinlib.transaction.hashlock import normalize_hashlock_utxo, PreparedHashlockSecret
```

#### prepare_hashlock_secret

**`prepare_hashlock_secret(secret: Union[str, bytes]) -> PreparedHashlockSecret`**
- Validate a secret and turn it into the on-chain preimage
- `str` is handled exactly like Tencoin Core (stripped, UTF-8, `TCS-` checksum verified); `bytes` is used unchanged (1–64 bytes)
- **Returns**: `PreparedHashlockSecret` with `.preimage` (bytes), `.hash` (32 bytes) and `.hash_hex`
- **Raises**: `InvalidHashlockSecretError`

#### verify_hashlock_secret

**`verify_hashlock_secret(secret: Union[str, bytes], expected_hash: Union[str, bytes]) -> bool`**
- `True` if `SHA-256(preimage)` equals `expected_hash` (bytes or hex); constant-time comparison
- **Returns**: `False` for a wrong secret
- **Raises**: `InvalidHashlockSecretError` for a malformed secret (bad TCS checksum, empty, too long); `InvalidHashlockUTXOError` for a malformed `expected_hash`

#### normalize_hashlock_utxo

**`normalize_hashlock_utxo(utxo: dict) -> HashlockUTXO`**
- Validate a C2 UTXO dict and return it in canonical form (`txid`, `vout`, `value`, `script_pubkey`, `secret_hash`, `owner_type` = `"p2wpkh"` or `"p2pkh"`, `owner_hash`)
- **Raises**: `InvalidHashlockUTXOError` (wrong `condition_flag`, bad fields, missing `secret_hash`, unsupported owner script)

#### build_hashlock_spend

**`build_hashlock_spend(utxo: dict, destination: str, amount: int = None, fee: int = None, secret: Union[str, bytes] = None, *, fee_rate: int = None, change_address: str = None) -> Transaction`**
- Build the **unsigned** transaction spending one HASHLOCK UTXO, using `TransactionBuilder`
- **Parameters**:
  - `amount` — Tenos to send; `None` sweeps the UTXO (value − fee)
  - `fee` — Exact fee in Tenos; `None` estimates it from `fee_rate` (default `FeeCalculator.DEFAULT_FEE_RATE` per vbyte, never below `MIN_RELAY_FEE`)
  - `secret` — Optional; if given it is verified against the UTXO, and its real size is used for the estimate (otherwise 64 bytes)
  - `change_address` — Required when `amount` leaves at least `DUST_LIMIT`; a smaller remainder is added to the fee
- **Raises**: `InvalidHashlockUTXOError`, `InvalidHashlockSecretError`, `HashlockSpendBuildError` (bad address, dust amount, fee ≥ value, insufficient funds, remainder that would be burned)

#### sign_hashlock_input

**`sign_hashlock_input(tx: Transaction, input_index: int, utxo: dict, private_key: bytes, secret: Union[str, bytes]) -> Transaction`**
- Sign input `input_index` in place and reveal the preimage (last item of the witness / scriptSig)
- Checks that the input spends the UTXO's outpoint, that the secret matches `secret_hash`, and that `private_key` owns the owner script
- **Raises**: `InvalidHashlockUTXOError`, `InvalidHashlockSecretError`, `HashlockSpendSigningError`

#### finalize_hashlock_spend

**`finalize_hashlock_spend(tx: Transaction) -> str`**
- Check that every input is signed, serialize the transaction and verify that it re-parses to the same txid
- **Returns**: Raw transaction hex
- **Raises**: `HashlockSpendSigningError` (unsigned input), `HashlockError` (empty transaction, negative output, serialization mismatch)

#### spend_hashlock

**`spend_hashlock(utxo: dict, private_key: bytes, destination: str, amount: int = None, fee: int = None, secret: Union[str, bytes] = None, *, fee_rate: int = None, change_address: str = None) -> HashlockSpendResult`**
- Build, sign (with an explicit key) and finalize in one call; `secret` is required
- **Returns**: `HashlockSpendResult` (`tx`, `raw_transaction`, `txid`, `fee`, `amount`, `change`, `secret_hash`)

### Secret Module

```python
from tencoinlib import (
    generate_secret, validate_secret, is_valid_tencoin_secret, check_secret,
    parse_secret, secret_to_preimage, hash_preimage, soft_warnings,
    SecretError, SecretFormatError,
)
```

**`generate_secret() -> str`**
- A new random 64-character `TCS-...` secret (CSPRNG), checksum included

**`validate_secret(secret: str) -> bool`** / **`is_valid_tencoin_secret(text: str) -> bool`**
- `True` only for a well-formed `TCS-` secret with a correct checksum; never raises (free-form text returns `False`)

**`check_secret(text: str) -> None`**
- Raises `SecretError` if the text starts with `TCS-` but is malformed or has a wrong checksum; free-form text passes

**`parse_secret(secret: str) -> ParsedSecret`**
- Split into `prefix`, `secret_body`, `checksum`, `text`, `checksum_valid` (and `.preimage`); a wrong checksum is reported by `checksum_valid` rather than raising
- **Raises**: `SecretError` if the text is not a well-formed `TCS-` secret (wrong prefix, length or characters)

**`secret_to_preimage(text: str, *, verify_checksum: bool = True) -> bytes`**
- Secret text → preimage: stripped, UTF-8 encoded, 1–64 bytes
- **Raises**: `SecretError`

**`hash_preimage(secret: str, *, verify_checksum: bool = True) -> bytes`**
- `SHA-256(preimage)` (single round) — the `secret_hash` of a HASHLOCK output

**`soft_warnings(text: str) -> List[str]`**
- Non-blocking warnings, e.g. text starting with `tcs-` in a different case (probably a generated secret whose case was changed)

**`class SecretError(ValueError)`** (alias `SecretFormatError`)
- Raised for malformed `TCS-` secrets, empty text, and preimages outside 1–64 bytes

### TMSG Module

```python
from tencoinlib import tmsg
```

#### Encryption and decryption

**`tmsg.encrypt(data: bytes, recipients, *, version: int = None, rpc=None) -> bytes`**
- Encrypt bytes to one or more public keys; returns the TMSG payload
- `recipients`: a key, a list of keys, or addresses (with `rpc`). `version=None` picks v1 for one key and v2 for several; forcing v1 needs exactly one key
- **Raises**: `TMSGKeyError`, `TMSGFormatError`, `TMSGSizeError`

**`tmsg.decrypt(payload: Union[bytes, str], private_keys) -> bytes`**
- Decrypt a payload (bytes or hex) with one private key or a list to try in order
- **Raises**: `TMSGFormatError` (not a TMSG), `TMSGDecryptionError` (wrong key or modified), `TMSGKeyError`

**`tmsg.encrypt_text(text: str, recipients, *, as_hex: bool = False, rpc=None) -> Union[bytes, str]`** / **`tmsg.decrypt_text(payload, private_keys) -> str`**
- UTF-8 text helpers; `decrypt_text` raises `TMSGFormatError` if the plaintext is not UTF-8

**`tmsg.inspect(payload) -> TMSGInfo`**
- Validate the structure without a key: `version`, `recipients`, `payload_size`, `overhead`, `plaintext_size`

**`tmsg.is_tmsg(data) -> bool`**, **`tmsg.overhead(recipients: int = 1, version: int = None) -> int`**, **`tmsg.max_plaintext(recipients: int = 1, version: int = None, limit: int = 1024) -> int`**, **`tmsg.select_version(recipients: int) -> int`**

#### Keys

**`tmsg.normalize_public_key(key, *, rpc=None) -> bytes`**, **`tmsg.parse_public_keys(recipients, *, rpc=None) -> List[bytes]`**
- Accept bytes (33/65), hex, several keys in one string, addresses (with `rpc`) or `PublicKeyInfo`; return validated 33-byte compressed keys (duplicates dropped, at most 255)

**`tmsg.normalize_private_key(key) -> bytes`**, **`tmsg.public_key_from_private_key(key) -> bytes`**

#### Files and folders

**`tmsg.encrypt_file(path, recipients, output=None, *, overwrite: bool = False, max_size: int = 1 GiB, rpc=None) -> FileResult`** / **`tmsg.decrypt_file(path, private_keys, output=None, *, overwrite: bool = False, max_size: int = 1 GiB) -> FileResult`**

**`tmsg.encrypt_folder(path, recipients, output=None, *, mode: str = "archive", overwrite: bool = False, max_size: int = 1 GiB, rpc=None) -> FolderResult`**
- `mode="archive"`: one `<name>.zip.enc`; `mode="files"`: `<name>_enc/` with `.enc` on every file. A `.zip` file is accepted as input

**`tmsg.decrypt_folder(path, private_keys, output=None, *, overwrite: bool = False, max_size: int = 1 GiB, max_extract_size: int = 4 GiB, max_files: int = 100000) -> FolderResult`**
- Accepts a `.zip.enc` file or a folder of `.enc` files; unsafe archive entries are skipped (`result.skipped`)

**`FileResult`**: `path`, `input_size`, `output_size`, `version`, `recipients`. **`FolderResult`**: `output`, `mode`, `files`, `input_size`, `output_size`, `version`, `recipients`, `errors`, `skipped`, `ok`.

#### On-chain

**`tmsg.build_tmsg_transaction(utxos, to_address, message, recipients=None, *, amount: int = 1, fee: int = None, fee_rate: int = None, change_address: str = None, rpc=None, select: bool = True, size_policy: str = "error", version: int = None) -> TMSGTransaction`**
- Build the unsigned transaction (output 0 payment, output 1 `OP_RETURN`, output 2 change). `select=True` spends the fewest, largest UTXOs; `select=False` spends all of them
- **Raises**: `TMSGError` (invalid arguments, insufficient funds, would burn more than dust), `TMSGSizeError`, `TMSGKeyError`

**`TMSGTransaction`**
- Attributes: `tx`, `payload`, `recipients`, `version`, `fee`, `amount`, `change`, `plaintext_size`, `padding`, `signed`, `broadcast_txid`, `txid`
- `sign(private_keys) -> TMSGTransaction`: sign every input (P2WPKH / P2PKH) with the key whose HASH160 matches; raises `TMSGKeyError` if an input has no key
- `raw_transaction`: hex for `send_raw_transaction`; raises `TMSGError` before `sign()`

**`tmsg.extract_tmsg_payloads(source, *, rpc=None) -> List[OnChainTMSG]`** (`output_index`, `payload`)

**`tmsg.decrypt_transaction(source, private_keys, *, rpc=None) -> List[DecryptedMessage]`** (`output_index`, `plaintext`, `text`)

**`tmsg.parse_op_return(script: bytes) -> Optional[bytes]`**, **`tmsg.op_return_script_length(data_length: int) -> int`**

### PublicKeyInfo

```python
from tencoinlib.rpc import PublicKeyInfo, public_key_matches_address, compress_public_key
```

**`PublicKeyInfo`** (returned by `rpc.get_public_key()`): `address`, `public_key` (bytes, as revealed on-chain), `public_key_hex`, `compressed` (33 bytes), `format` (`"compressed"` or `"uncompressed"`), `txid`, `input_index`, `location` (`"witness"` or `"scriptSig"`), `height`, `node_verified`

**`public_key_matches_address(pubkey: bytes, address: str) -> bool`**
- `True` if the key is the one behind a P2PKH, P2WPKH or P2SH-P2WPKH address

**`compress_public_key(pubkey: bytes) -> bytes`**
- 33-byte compressed form of a 33- or 65-byte key; `ValueError` if the point is not on secp256k1

---

## Error Handling

### Exception Classes

```python
from tencoinlib import WalletError, WalletLockedError, WalletAuthError
from tencoinlib.wallet_storage.tcw import TCWFormatError, TCWVersionError, TCWAuthError
from tencoinlib.wallet_storage.tce import TCEError, TCEFormatError, TCEAuthError, TCEVersionError
from tencoinlib.wallet_storage.esp_bridge import ESPBridgeError
from tencoinlib.transaction import (
    TransactionBuilderError,
    SigningError,
    AddressError
)
from tencoinlib.rpc import (
    RPCError,
    ConnectionError,
    AuthenticationError,
    TimeoutError,
    ResponseError,
    InvalidMethodError
)
from tencoinlib.message import MessageSigningError
from tencoinlib import (
    HashlockError,
    InvalidHashlockSecretError,
    InvalidHashlockUTXOError,
    HashlockSpendBuildError,
    HashlockSpendSigningError,
    SecretError,
    TMSGError,
    TMSGKeyError,
    TMSGFormatError,
    TMSGDecryptionError,
    TMSGSizeError,
)
```

### Wallet Errors

```python
from tencoinlib import Wallet, WalletError, WalletLockedError, WalletAuthError
from tencoinlib.wallet_storage.tcw import TCWFormatError, TCWVersionError

# Invalid mnemonic
try:
    wallet = Wallet.recover("invalid mnemonic")
except WalletError as e:
    print(f"Wallet error: {e}")

# Wrong password
try:
    wallet = Wallet.load("my_wallet.tcw").unlock("wrong-password")
except WalletAuthError:
    print("Wrong password or file is corrupted")

# Operation on a locked wallet
wallet = Wallet.load("my_wallet.tcw")   # LOCKED
try:
    wallet.get_mnemonic()               # requires UNLOCKED
except WalletLockedError as e:
    print(f"Wallet is locked: {e}")

# Invalid or unsupported .tcw file
try:
    wallet = Wallet.load("not_a_wallet.bin")
except TCWFormatError as e:
    print(f"Not a valid TCW file: {e}")
except TCWVersionError as e:
    print(f"Unsupported TCW version: {e}")
```

### ESP Bridge Errors

```python
from tencoinlib.wallet_storage.tce import TCEAuthError, TCEFormatError
from tencoinlib.wallet_storage.esp_bridge import ESPBridgeError

try:
    blob = wallet.export_to_esp_blob(esp_password="device-password")
except ESPBridgeError as e:
    print(f"Wallet type has no ESP equivalent: {e}")

try:
    wallet = Wallet.import_from_esp_blob(blob, esp_password="wrong-password")
except TCEAuthError:
    print("Wrong ESP password or corrupted blob")
except TCEFormatError as e:
    print(f"Not a valid TCE1 blob: {e}")
```

### Transaction Errors

```python
from tencoinlib.transaction import (
    TransactionBuilder,
    TransactionBuilderError,
    AddressError
)

try:
    builder = TransactionBuilder()
    builder.add_output("invalid-address", 1000)
except AddressError:
    print("Invalid address")
except TransactionBuilderError as e:
    print(f"Transaction builder error: {e}")
```

### Message Signing Errors

```python
from tencoinlib import sign_message, verify_message, MessageSigningError

try:
    signature = sign_message(private_key, "Hello Tencoin!")
except MessageSigningError as e:
    print(f"Signing error: {e}")

try:
    is_valid = verify_message(address, "Hello Tencoin!", signature)
except MessageSigningError as e:
    print(f"Verification error: {e}")
```

### Signing Errors

```python
from tencoinlib import TransactionSigner, LegacySigner, SegWitSigner, SigningError

# Universal signer (recommended)
try:
    signed_tx = TransactionSigner.sign_transaction(tx, utxos, keys)
except SigningError as e:
    print(f"Signing error: {e}")

# Legacy signer
try:
    signed_tx = LegacySigner.sign_transaction(tx, utxos, keys)
except SigningError as e:
    print(f"Legacy signing error: {e}")

# SegWit signer
try:
    signed_tx = SegWitSigner.sign_transaction(tx, utxos, keys)
except SigningError as e:
    print(f"SegWit signing error: {e}")
```

### Hashlock Errors

```
HashlockError(Exception)                       base class
├── InvalidHashlockSecretError(ValueError)     malformed secret (bad TCS checksum, empty, > 64 bytes) or secret does not match the UTXO's hash
├── InvalidHashlockUTXOError(ValueError)       not a usable C2 UTXO (wrong flag, bad fields, no secret_hash, unsupported owner script)
├── HashlockSpendBuildError(ValueError)        bad destination / amount / fee, or the transaction cannot be built
└── HashlockSpendSigningError(SigningError)    wrong key, outpoint mismatch, unsigned input at finalize
```

```python
from tencoinlib import (
    HashlockError, InvalidHashlockSecretError, InvalidHashlockUTXOError,
    HashlockSpendBuildError, HashlockSpendSigningError,
)
from tencoinlib.wallet import WalletLockedError

try:
    with wallet.unlocked(password):
        result = wallet.spend_hashlock(utxo, destination, secret=secret)
except InvalidHashlockSecretError as e:
    print(f"Secret problem: {e}")            # typo in a TCS secret, or the wrong secret
except InvalidHashlockUTXOError as e:
    print(f"Not a spendable HASHLOCK UTXO: {e}")
except HashlockSpendBuildError as e:
    print(f"Cannot build the transaction: {e}")   # fee too high, missing change_address, bad address, ...
except HashlockSpendSigningError as e:
    print(f"Cannot sign: {e}")               # this wallet's keys do not own the UTXO
except WalletLockedError:
    print("Unlock the wallet first")
except HashlockError as e:
    print(f"Hashlock error: {e}")
```

Errors from `add_hashlock_output()` (creating a HASHLOCK output) are `TransactionBuilderError`; the `TCS-` helpers (`secret_to_preimage()`, `check_secret()`, ...) raise `SecretError`.

### TMSG Errors

```
TMSGError(Exception)                       base class
├── TMSGKeyError(ValueError)               invalid / unresolvable public or private key, too many recipients
├── TMSGFormatError(ValueError)            not a TMSG payload (magic, version, length, hex, archive)
├── TMSGDecryptionError(ValueError)        wrong key, or the payload was modified
├── TMSGSizeError(ValueError)              does not fit, or an unsafe OP_RETURN size (.size, .limit, .pad_bytes)
└── TMSGDependencyError(ImportError)       coincurve / cryptography missing
```

```python
from tencoinlib import tmsg
from tencoinlib.rpc import PublicKeyNotFoundError, PublicKeyVerificationError

try:
    tx = tmsg.build_tmsg_transaction(utxos, to, text, rpc=rpc, change_address=addr)
except PublicKeyNotFoundError:
    print("The recipient never spent from that address: ask them for their public key")
except PublicKeyVerificationError:
    print("The node returned a key that does not match the address")
except tmsg.TMSGSizeError as e:
    print(f"Message does not fit or has an unsafe size: {e}")      # e.pad_bytes: add this many bytes
except tmsg.TMSGError as e:
    print(f"Cannot build the TMSG transaction: {e}")

try:
    text = tmsg.decrypt_text(payload, private_key)
except tmsg.TMSGDecryptionError:
    print("Wrong key, or the message was modified")
except tmsg.TMSGFormatError:
    print("Not a TMSG payload")
```

### RPC Errors

```python
from tencoinlib.rpc import (
    RPCClient,
    ConnectionError,
    AuthenticationError,
    TimeoutError,
    ResponseError,
    PublicKeyNotFoundError,        # getpublickey: the address never spent, so no key is on-chain
    PublicKeyVerificationError     # getpublickey: the node's key does not match the address
)

try:
    rpc = RPCClient(host="invalid", port=10111)
except ConnectionError as e:
    print(f"Connection error: {e}")

try:
    balance = rpc.get_balance("tc1q...")
except AuthenticationError:
    print("Authentication failed")
except TimeoutError:
    print("Request timeout")
except ResponseError as e:
    print(f"Response error: {e}")
except RPCError as e:
    print(f"RPC error: {e}")
```

---

## Constants and Configuration

### Main Constants

```python
from tencoinlib import (
    MAINNET_HRP,           # "tc" - Human Readable Part for Bech32
    TENOS_PER_TEC,         # 100000000 - Number of Tenos in one TEC
    DUST_LIMIT,            # 546 - Minimum spendable amount
    DEFAULT_RPC_PORT,      # 10111 - Default RPC port
    DEFAULT_RPC_TOKEN,     # "" - Default RPC token
    COIN_TYPE,             # 5353 - Coin type for BIP-44-style paths
    DERIVATION_PATH        # "m/44'/5353'/0'/0/0" - Default BIP-44 (P2PKH) derivation path
)
```

### Fee Constants

```python
from tencoinlib.transaction import FeeCalculator

FeeCalculator.DEFAULT_FEE_RATE    # 20 Tenos/byte
FeeCalculator.PRIORITY_FEE_RATE   # 50 Tenos/byte
FeeCalculator.ECONOMY_FEE_RATE    # 10 Tenos/byte
```

### TMSG and OP_RETURN Constants

```python
from tencoinlib.tmsg import (
    TMSG_MAGIC,            # b"TMSG"
    TMSG_VERSION_1,        # 0x01 - one recipient key
    TMSG_VERSION_2,        # 0x02 - 2..255 recipient keys
    TMSG_MAX_RECIPIENTS,   # 255
    TMSG_MIN_PAYMENT,      # 1 Teno - minimum payment of a TMSG transaction (the dust limit does not apply)
    OP_RETURN_MAX_DATA,    # 1024 - data bytes allowed in an OP_RETURN output
)
from tencoinlib.constants import (
    OUTPUT_FLAG_RANGE,     # range(0xC1, 0xD0) - OP_RETURN scripts of 193..207 bytes are never produced
    TMSG_GCM_TAG_SIZE,     # 16
    TMSG_NONCE_SIZE,       # 12
)
```

### HASHLOCK and Secret Constants

```python
from tencoinlib import (
    COND_FLAG_HASHLOCK,       # 0xC2 - HASHLOCK conditional output flag
    HASHLOCK_MIN_PREIMAGE,    # 1  - Minimum preimage size in bytes
    HASHLOCK_MAX_PREIMAGE,    # 64 - Maximum preimage size in bytes
    HASHLOCK_HASH_SIZE,       # 32 - Size of secret_hash (SHA-256, single round)
)
from tencoinlib.constants import (
    SECRET_PREFIX,            # "TCS-"
    SECRET_BODY_LENGTH,       # 55 random characters
    SECRET_CHECKSUM_LENGTH,   # 5 checksum characters
    SECRET_TOTAL_LENGTH,      # 64 characters in total (the prefix is counted)
)
```

### Address Constants

```python
from tencoinlib.constants import (
    P2PKH_VERSION,    # 0x41 - Address version for P2PKH (legacy 'T...' addresses)
    P2SH_VERSION,     # 0x32 - Address version for P2SH (legacy 'M...' addresses)
    P2WPKH_VERSION    # 0     - Witness version for P2WPKH (SegWit 'tc1q...' addresses)
)
```

### BIP-32 Purpose Constants

```python
from tencoinlib.constants import (
    BIP44_PURPOSE,    # 44 - Legacy P2PKH
    BIP49_PURPOSE,    # 49 - Nested SegWit (P2SH-P2WPKH)
    BIP84_PURPOSE,    # 84 - Native SegWit (P2WPKH)
)
```

---

## Best Practices

### Message Signing

1. **Always use P2PKH addresses for message signing**
   ```python
   # Correct — use P2PKH address (T...)
   address = wallet.get_address("p2pkh")
   is_valid = verify_message(address, message, signature)
   ```

2. **Verify before trusting**
   - Always call `verify_message()` on receipt before acting on a signed claim.

3. **Sign file hashes, not file contents**
   - Pass the hex SHA256 digest of a file as the message to keep signatures portable and reproducible.

4. **Do not reuse signatures across contexts**
   - A valid signature proves ownership at the time of signing. Include timestamps or nonces in the message when freshness matters.

---

### Security

1. **Always save wallets to encrypted `.tcw` files**
   ```python
   wallet.save("my_wallet.tcw", password="strong-password")
   ```
   Never store raw mnemonics or private keys in plaintext files.

2. **Keep wallets locked when not in use**
   ```python
   # Preferred: context manager auto-locks on exit
   with wallet.unlocked("my-password") as w:
       signed_tx = w.sign_transaction(tx)

   # Or lock explicitly
   wallet.unlock("my-password")
   # ... do work ...
   wallet.lock()
   ```

3. **Use BIP-39 passphrases for additional protection**
   ```python
   wallet = Wallet.recover(mnemonic, passphrase="strong-passphrase")
   ```
   The passphrase is separate from the file encryption password and provides a second layer of security.

4. **Use strong, unique passwords for wallet files**
   - Minimum 8 characters (enforced)
   - Argon2id KDF makes brute-force attacks expensive
   - A strong password is the last line of defence if the `.tcw` file is stolen

5. **Back up the mnemonic phrase — not the `.tcw` file**
   - The `.tcw` file can always be recreated from the mnemonic
   - Store the mnemonic offline and in a physically secure location
   - Never commit mnemonics or `.tcw` files to version control

6. **Validate addresses before sending**
   ```python
   from tencoinlib.transaction import is_valid_address
   if not is_valid_address(recipient_address):
       raise ValueError("Invalid recipient address")
   ```

7. **Double-check transaction details**
   - Always verify recipient address
   - Confirm amount before broadcasting
   - Check fee is reasonable

8. **Use change addresses**
   - Always set a change address to protect privacy
   - Use new change addresses for each transaction

### TMSG Messages

1. **Check the key before you encrypt**
   - A wrong public key sends your message to someone else. Prefer `rpc.get_public_key()` (verified against the address) or a key the owner gave you directly; never type keys from memory
   - Pass the recipient's address together with `rpc=rpc` instead of copying the key by hand

2. **Remember that TMSG does not identify the sender**
   - Anyone can encrypt to a public key. If the sender must be provable, sign the plaintext (Message Signing) or include a signature in the message

3. **Encrypt to yourself too** if you need to read what you sent
   - `include_self=True` in `wallet.send_tmsg()`, or add your own public key to `recipients` (this makes it a v2 message: 93 bytes more overhead per recipient)

4. **Keep recipient lists small on-chain**
   - Every recipient costs 93 bytes of the 1024-byte `OP_RETURN`; for large groups encrypt a file off-chain and send only its location / hash

5. **Dry-run before broadcasting**
   - `rpc.test_mempool_accept(tx.raw_transaction)`; a data-carrying transaction may need a higher fee than the default (`fee_rate=` / `fee=`)

6. **Mind the private key**
   - Whoever holds the private key can read every message encrypted to its public key, past and future. Rotate to a new address and key for new conversations if a key may have leaked

7. **Be careful with unknown encrypted archives**
   - `decrypt_folder()` skips unsafe paths and bounds the output size, but still extract into a folder you can throw away, and lower `max_extract_size` if you expect small archives

### HASHLOCK Secrets

1. **Generate secrets with `generate_secret()`**
   - It uses the operating system's CSPRNG and adds the typo-catching checksum
   - Use a fresh secret for every lock: the preimage becomes public when the spend is broadcast

2. **Never log or store a whole secret**
   - Log at most the first 8 characters, or the hash (`hash_preimage(secret)`)

3. **Keep the secret text exact**
   - The whole text is the preimage: do not change its case, re-group it or re-encode it
   - Only the two ends are stripped

4. **Verify before you sign and broadcast**
   ```python
   if not verify_hashlock_secret(secret, utxo["secret_hash"]):
       raise ValueError("This is not the secret for this UTXO")
   ```

5. **Test before sending a real amount**
   - Check `rpc.test_mempool_accept(result.raw_transaction)` or start with a small amount; the library cannot validate the transaction against the node's consensus rules

6. **Remember that both halves are needed**
   - To let someone claim a HASHLOCK output, lock it to their address *and* give them the secret

### Performance

1. **Use SegWit**
   - SegWit transactions have lower fees
   - Faster confirmation times
   - Smaller transaction size

2. **Manage UTXOs efficiently**
   - Consolidate small UTXOs periodically
   - Too many small UTXOs increase fees

3. **Optimize fee rates**
   - Use appropriate fee rate for your needs
   - Priority: Fast confirmation (higher fee)
   - Normal: Standard confirmation (default fee)
   - Economy: Slow confirmation (lower fee)

### Transaction Building

1. **Check sufficient funds before building**
   ```python
   total_needed = amount + estimated_fee
   if total_available < total_needed:
       raise ValueError("Insufficient funds")
   ```

2. **Handle dust outputs**
   - Change below dust limit is added to fee
   - Minimum output: 546 Tenos

3. **Use transaction summary**
   ```python
   summary = builder.get_summary()
   # Review before building
   ```

4. **Test transactions first**
   ```python
   # Test before broadcasting
   result = rpc.test_mempool_accept(tx_hex)
   if result.get("allowed"):
       txid = rpc.send_raw_transaction(tx_hex)
   ```

### Error Handling

1. **Always use try/except blocks**
   ```python
   try:
       wallet = Wallet.recover(mnemonic)
   except WalletError as e:
       # Handle error appropriately
       pass
   ```

2. **Check connection before RPC calls**
   ```python
   try:
       rpc = RPCClient(...)
       balance = rpc.get_balance(address)
   except ConnectionError:
       # Handle connection issue
       pass
   ```

### Code Organization

1. **Separate concerns**
   - Wallet management
   - Transaction building
   - RPC interaction

2. **Reuse transaction builders**
   ```python
   builder = TransactionBuilder()
   # Reuse for multiple transactions
   builder.clear()
   ```

3. **Cache RPC results when appropriate**
   - Balance queries
   - UTXO lists (for short periods)

---
# tencoinlib/transaction/hashlock.py
"""
Spending of HASHLOCK (0xC2) conditional outputs.

Locking side (creating a C2 output) lives in ``TransactionBuilder.add_hashlock_output``
and ``HashlockTxOut``.  This module is the UNLOCKING side.

On-chain rule (same as the reference wallet)
--------------------------------------------
A C2 output is  ``[value][0xC2][secret_hash 32B][script_len][script_pubkey]``.
``script_pubkey`` is an ordinary owner script (P2PKH or P2WPKH), so spending needs
BOTH the owner's signature AND the secret preimage. The node checks
``SHA256(preimage) == secret_hash`` and the preimage is the LAST unlocking item:

    P2WPKH owner  ->  witness   = [ sig , pubkey , preimage ]
    P2PKH  owner  ->  scriptSig = <sig> <pubkey> <preimage>

The signature hash is the normal BIP-143 (P2WPKH) / legacy (P2PKH) digest of the
owner script. Outputs are hashed with their own ``serialize()``, so conditional
outputs are committed to exactly as they appear on the wire.

Typical use
-----------
    from tencoinlib.transaction.hashlock import spend_hashlock

    result = spend_hashlock(
        utxo={"txid": ..., "vout": 0, "value": 5_000_000,
              "script_pubkey": "0014...", "secret_hash": "ab12..."},
        private_key=priv32,
        destination="tc1q...",
        secret="TCS-....",
    )
    node.sendrawtransaction(result.raw_transaction)

Step by step: ``prepare_hashlock_secret`` -> ``verify_hashlock_secret`` ->
``build_hashlock_spend`` -> ``sign_hashlock_input`` -> ``finalize_hashlock_spend``.

NEVER log a whole secret (see secret.py): log at most its hash.
"""

import hashlib
import hmac
from typing import Any, Mapping, NamedTuple, Optional, Union

from ..constants import (
    COND_FLAG_HASHLOCK,
    DUST_LIMIT,
    HASHLOCK_HASH_SIZE,
    HASHLOCK_MAX_PREIMAGE,
    HASHLOCK_MIN_PREIMAGE,
    MIN_RELAY_FEE,
)
from ..secret import SecretError, secret_to_preimage
from ..utils import hash160
from .address import AddressError, address_to_script
from .builder import TransactionBuilder, TransactionBuilderError
from .core import Transaction, TxIn, TxOut, parse_transaction
from .fee import FeeCalculator
from .signer import LegacySigner, SegWitSigner, SigningError, _push_data

__all__ = [
    "HashlockError",
    "InvalidHashlockSecretError",
    "InvalidHashlockUTXOError",
    "HashlockSpendBuildError",
    "HashlockSpendSigningError",
    "PreparedHashlockSecret",
    "HashlockUTXO",
    "HashlockSpendResult",
    "prepare_hashlock_secret",
    "verify_hashlock_secret",
    "normalize_hashlock_utxo",
    "build_hashlock_spend",
    "sign_hashlock_input",
    "finalize_hashlock_spend",
    "spend_hashlock",
]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class HashlockError(Exception):
    """Base class for all hashlock-spend errors."""


class InvalidHashlockSecretError(HashlockError, ValueError):
    """Secret is malformed (bad TCS checksum, empty, > 64 bytes) or does not match the lock."""


class InvalidHashlockUTXOError(HashlockError, ValueError):
    """UTXO is not a usable C2 HASHLOCK output (wrong flag, bad fields, unsupported owner script)."""


class HashlockSpendBuildError(HashlockError, ValueError):
    """Bad destination / amount / fee, or the transaction cannot be built."""


class HashlockSpendSigningError(HashlockError, SigningError):
    """Signing failed (wrong key, unsigned input at finalize, outpoint mismatch, ...)."""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class PreparedHashlockSecret(NamedTuple):
    preimage: bytes     # exact bytes revealed on-chain (1..64)
    hash: bytes         # SHA-256(preimage), 32 bytes

    @property
    def hash_hex(self) -> str:
        return self.hash.hex()


class HashlockUTXO(NamedTuple):
    txid: str
    vout: int
    value: int
    script_pubkey: bytes   # owner script (P2PKH / P2WPKH)
    secret_hash: bytes     # 32 bytes committed by the C2 output
    owner_type: str        # "p2wpkh" | "p2pkh"
    owner_hash: bytes      # 20-byte pubkey hash of the owner


class HashlockSpendResult(NamedTuple):
    tx: Transaction
    raw_transaction: str   # hex, ready for sendrawtransaction
    txid: str
    fee: int               # Tenos
    amount: int            # Tenos sent to the destination
    change: int            # Tenos returned to change_address (0 if none)
    secret_hash: str       # hex


# ---------------------------------------------------------------------------
# Secret helpers
# ---------------------------------------------------------------------------

def prepare_hashlock_secret(secret: Union[str, bytes, bytearray]) -> PreparedHashlockSecret:
    """
    Validate a secret and turn it into the on-chain preimage.

    * ``str``   : handled exactly like the node (``secret_to_preimage``): stripped,
                  UTF-8 encoded, TCS- checksum verified when the text claims to be a
                  Tencoin secret. The WHOLE text (prefix + checksum) is the preimage.
    * ``bytes`` : used as the raw preimage, unchanged (1..64 bytes).

    Raises:
        InvalidHashlockSecretError
    """
    if isinstance(secret, (bytes, bytearray)):
        preimage = bytes(secret)
        if len(preimage) < HASHLOCK_MIN_PREIMAGE:
            raise InvalidHashlockSecretError(
                f"Preimage too short ({len(preimage)} bytes), minimum is {HASHLOCK_MIN_PREIMAGE}"
            )
        if len(preimage) > HASHLOCK_MAX_PREIMAGE:
            raise InvalidHashlockSecretError(
                f"Preimage too long ({len(preimage)} bytes), maximum is {HASHLOCK_MAX_PREIMAGE}"
            )
    elif isinstance(secret, str):
        try:
            preimage = secret_to_preimage(secret)
        except SecretError as exc:
            raise InvalidHashlockSecretError(str(exc)) from exc
    else:
        raise InvalidHashlockSecretError(
            f"secret must be str or bytes, got {type(secret).__name__}"
        )
    return PreparedHashlockSecret(preimage, hashlib.sha256(preimage).digest())


def _coerce_hash(value: Any, what: str = "secret_hash") -> bytes:
    if isinstance(value, str):
        try:
            value = bytes.fromhex(value.strip())
        except ValueError:
            raise InvalidHashlockUTXOError(f"{what} is not valid hex") from None
    if not isinstance(value, (bytes, bytearray)) or len(value) != HASHLOCK_HASH_SIZE:
        raise InvalidHashlockUTXOError(f"{what} must be exactly {HASHLOCK_HASH_SIZE} bytes")
    return bytes(value)


def verify_hashlock_secret(
    secret: Union[str, bytes, bytearray],
    expected_hash: Union[str, bytes, bytearray],
) -> bool:
    """
    True if SHA-256(preimage of ``secret``) equals ``expected_hash`` (bytes or hex).

    A wrong secret returns False. A *malformed* secret (typo in a TCS- checksum, empty,
    too long) raises InvalidHashlockSecretError, so typos are told apart from wrong
    secrets. A malformed ``expected_hash`` raises InvalidHashlockUTXOError.
    """
    prepared = prepare_hashlock_secret(secret)
    return hmac.compare_digest(prepared.hash, _coerce_hash(expected_hash, "expected_hash"))


# ---------------------------------------------------------------------------
# UTXO normalisation
# ---------------------------------------------------------------------------

_SCRIPT_KEYS = ("script_pubkey", "scriptPubKey", "scriptpubkey")
_HASH_KEYS = ("secret_hash", "hashlock", "hash")


def _first(d: Mapping, keys) -> Any:
    for k in keys:
        if d.get(k) is not None:
            return d[k]
    return None


def normalize_hashlock_utxo(utxo: Mapping) -> HashlockUTXO:
    """
    Validate a C2 UTXO dict and return it in canonical form.

    Required keys: ``txid``, ``vout``, ``value`` (Tenos), the owner script
    (``script_pubkey`` as bytes/hex, or ``address``) and ``secret_hash`` (bytes/hex).
    If ``condition_flag`` is present it must be 0xC2.

    Raises:
        InvalidHashlockUTXOError
    """
    if not isinstance(utxo, Mapping):
        raise InvalidHashlockUTXOError("utxo must be a dict")

    flag = utxo.get("condition_flag")
    if flag is not None and flag != COND_FLAG_HASHLOCK:
        raise InvalidHashlockUTXOError(
            f"Not a HASHLOCK UTXO: condition_flag is 0x{int(flag):02x}, expected 0xc2"
        )

    txid = utxo.get("txid")
    if not isinstance(txid, str) or len(txid) != 64:
        raise InvalidHashlockUTXOError("txid must be a 64-char hex string")
    try:
        bytes.fromhex(txid)
    except ValueError:
        raise InvalidHashlockUTXOError("txid is not valid hex") from None

    vout, value = utxo.get("vout"), utxo.get("value")
    if isinstance(vout, bool) or not isinstance(vout, int) or vout < 0:
        raise InvalidHashlockUTXOError(f"Invalid vout: {vout!r}")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InvalidHashlockUTXOError(f"Invalid value (Tenos, positive int): {value!r}")

    script = _first(utxo, _SCRIPT_KEYS)
    if script is None and utxo.get("address"):
        try:
            script = address_to_script(utxo["address"])
        except AddressError as exc:
            raise InvalidHashlockUTXOError(f"Invalid address: {exc}") from exc
    if isinstance(script, str):
        try:
            script = bytes.fromhex(script.strip())
        except ValueError:
            raise InvalidHashlockUTXOError("script_pubkey is not valid hex") from None
    if not isinstance(script, (bytes, bytearray)) or not script:
        raise InvalidHashlockUTXOError("UTXO has no script_pubkey (or address)")
    script = bytes(script)

    secret_hash = _first(utxo, _HASH_KEYS)
    if secret_hash is None:
        raise InvalidHashlockUTXOError(
            "UTXO has no secret_hash: it is required to verify the secret before signing"
        )
    secret_hash = _coerce_hash(secret_hash)

    if len(script) == 22 and script[:2] == b"\x00\x14":
        owner_type, owner_hash = "p2wpkh", script[2:]
    elif (len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac"):
        owner_type, owner_hash = "p2pkh", script[3:23]
    else:
        raise InvalidHashlockUTXOError(
            "Unsupported owner script: only P2PKH and P2WPKH hashlock owners can be spent"
        )

    return HashlockUTXO(txid.lower(), vout, value, script, secret_hash, owner_type, owner_hash)


# ---------------------------------------------------------------------------
# Size estimate (used only when no explicit fee is given)
# ---------------------------------------------------------------------------

def _unlock_dummy(owner_type: str, preimage_len: int):
    sig, pub, pre = b"\x00" * 73, b"\x00" * 33, b"\x00" * preimage_len
    if owner_type == "p2wpkh":
        return b"", [sig, pub, pre]
    return _push_data(sig) + _push_data(pub) + _push_data(pre), []


def _estimate_size(u: HashlockUTXO, outputs, preimage_len: int) -> int:
    script_sig, witness = _unlock_dummy(u.owner_type, preimage_len)
    tmp = Transaction(
        version=1,
        vin=[TxIn(u.txid, u.vout, script_sig=script_sig, witness=witness)],
        vout=list(outputs),
    )
    return tmp.calculate_vsize()


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_hashlock_spend(
    utxo: Mapping,
    destination: str,
    amount: Optional[int] = None,
    fee: Optional[int] = None,
    secret: Union[str, bytes, bytearray, None] = None,
    *,
    fee_rate: Optional[int] = None,
    change_address: Optional[str] = None,
) -> Transaction:
    """
    Build the UNSIGNED transaction spending one C2 UTXO.

    Args:
        utxo:           see normalize_hashlock_utxo().
        destination:    address receiving ``amount``.
        amount:         Tenos to send. None = sweep: everything minus the fee.
        fee:            exact fee in Tenos. None = estimate from ``fee_rate``
                        (default FeeCalculator.DEFAULT_FEE_RATE per vbyte, floor MIN_RELAY_FEE).
        secret:         optional; if given it is validated against the UTXO's hash
                        now, and its real size is used for the fee estimate
                        (otherwise the 64-byte maximum is assumed).
        change_address: required when ``amount`` leaves >= DUST_LIMIT behind;
                        otherwise the build is refused instead of burning the rest as fee.

    A remainder below DUST_LIMIT is added to the fee (same as TransactionBuilder).

    Raises:
        InvalidHashlockUTXOError, InvalidHashlockSecretError, HashlockSpendBuildError
    """
    u = normalize_hashlock_utxo(utxo)

    preimage_len = HASHLOCK_MAX_PREIMAGE
    if secret is not None:
        prepared = prepare_hashlock_secret(secret)
        if not hmac.compare_digest(prepared.hash, u.secret_hash):
            raise InvalidHashlockSecretError(
                "SHA256(preimage) does not match the secret_hash of this UTXO (wrong secret)"
            )
        preimage_len = len(prepared.preimage)

    try:
        dest_script = address_to_script(destination)
        change_script = address_to_script(change_address) if change_address else None
    except (AddressError, ValueError) as exc:
        raise HashlockSpendBuildError(f"Invalid address: {exc}") from exc

    for name, v in (("amount", amount), ("fee", fee)):
        if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 0):
            raise HashlockSpendBuildError(f"{name} must be a non-negative integer (Tenos), got {v!r}")
    if amount is not None and amount < DUST_LIMIT:
        raise HashlockSpendBuildError(f"amount {amount} is below the dust limit ({DUST_LIMIT})")

    # --- fee ---------------------------------------------------------------
    if fee is None:
        rate = FeeCalculator.DEFAULT_FEE_RATE if fee_rate is None else fee_rate
        if isinstance(rate, bool) or not isinstance(rate, int) or rate <= 0:
            raise HashlockSpendBuildError(f"fee_rate must be a positive integer, got {rate!r}")
        guess = [TxOut(max(amount or u.value, 1), dest_script)]
        if amount is not None and change_script:
            guess.append(TxOut(DUST_LIMIT, change_script))
        fee = max(_estimate_size(u, guess, preimage_len) * rate, MIN_RELAY_FEE)

    # --- amounts -----------------------------------------------------------
    if fee >= u.value:
        raise HashlockSpendBuildError(f"Fee ({fee}) exceeds or equals UTXO value ({u.value})")
    if amount is None:
        amount = u.value - fee
        if amount < DUST_LIMIT:
            raise HashlockSpendBuildError(
                f"Nothing left after fee: UTXO {u.value} - fee {fee} = {amount} (< dust {DUST_LIMIT})"
            )
    leftover = u.value - amount - fee
    if leftover < 0:
        raise HashlockSpendBuildError(
            f"Insufficient funds: UTXO {u.value} < amount {amount} + fee {fee}"
        )
    if leftover >= DUST_LIMIT and not change_address:
        raise HashlockSpendBuildError(
            f"{leftover} Tenos would be burned as extra fee: pass change_address, "
            "or omit amount to sweep the whole UTXO"
        )

    # --- assemble via the standard builder ----------------------------------
    try:
        b = TransactionBuilder()
        b.add_input(u.txid, u.vout, u.value, u.script_pubkey)
        b.add_output(destination, amount)
        if change_address and leftover >= DUST_LIMIT:
            b.set_change_address(change_address)
        b.set_fee(fee)
        b.set_segwit(u.owner_type == "p2wpkh")
        tx, _ = b.build()
    except TransactionBuilderError as exc:
        raise HashlockSpendBuildError(str(exc)) from exc
    return tx


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------

def sign_hashlock_input(
    tx: Transaction,
    input_index: int,
    utxo: Mapping,
    private_key: bytes,
    secret: Union[str, bytes, bytearray],
) -> Transaction:
    """
    Sign input ``input_index`` of ``tx`` (in place) and reveal the preimage.

    The utxo is needed (not just the tx) because the signature commits to its value
    and owner script, and because the secret is verified against its secret_hash first.
    Other inputs are left untouched, so several C2 inputs / ordinary inputs can be
    signed one after another. Sign ordinary inputs with TransactionSigner BEFORE the
    hashlock inputs: TransactionSigner returns a copy that drops existing witnesses.

    Raises:
        InvalidHashlockUTXOError, InvalidHashlockSecretError, HashlockSpendSigningError
    """
    u = normalize_hashlock_utxo(utxo)

    if not isinstance(input_index, int) or not 0 <= input_index < len(tx.vin):
        raise HashlockSpendSigningError(f"input_index {input_index!r} out of range")
    txin = tx.vin[input_index]
    if txin.prev_txid.lower() != u.txid or txin.vout != u.vout:
        raise HashlockSpendSigningError(
            f"Input {input_index} spends {txin.prev_txid}:{txin.vout}, "
            f"but the given UTXO is {u.txid}:{u.vout}"
        )

    prepared = prepare_hashlock_secret(secret)
    if not hmac.compare_digest(prepared.hash, u.secret_hash):
        raise InvalidHashlockSecretError(
            "SHA256(preimage) does not match the secret_hash of this UTXO (wrong secret)"
        )

    from ..keys.wif import WIFError, to_private_key_bytes
    try:
        private_key = to_private_key_bytes(private_key)     # 32 bytes, hex or WIF (any form)
    except WIFError as exc:
        raise HashlockSpendSigningError(f"invalid private key: {exc}") from exc
    try:
        from ..keys.ec import sign
        from ..keys.pubkey import public_key_for_hash160
        # SegWit owners need the compressed key; legacy P2PKH owners may use either form
        pub = public_key_for_hash160(
            private_key, u.owner_hash, allow_uncompressed=(u.owner_type == "p2pkh")
        )
    except Exception as exc:
        raise HashlockSpendSigningError(f"Invalid private key: {exc}") from exc
    if pub is None:
        raise HashlockSpendSigningError(
            "This private key does not own the UTXO (pubkey hash differs from the owner script)"
        )

    try:
        if u.owner_type == "p2wpkh":
            script_code = bytes([0x76, 0xA9, 0x14]) + u.owner_hash + bytes([0x88, 0xAC])
            sig = SegWitSigner.create_witness_signature(
                tx, input_index, private_key, script_code, u.value
            )
            txin.script_sig = b""
            txin.witness = [sig, pub, prepared.preimage]      # preimage LAST
            tx.has_witness = True
        else:
            digest = LegacySigner.legacy_digest(tx, input_index, u.script_pubkey, 1)
            sig = sign(private_key, digest) + b"\x01"
            txin.script_sig = _push_data(sig) + _push_data(pub) + _push_data(prepared.preimage)
            txin.witness = []
    except SigningError as exc:
        raise HashlockSpendSigningError(str(exc)) from exc
    except Exception as exc:
        raise HashlockSpendSigningError(f"Failed to sign input {input_index}: {exc}") from exc
    return tx


# ---------------------------------------------------------------------------
# Finalize
# ---------------------------------------------------------------------------

def finalize_hashlock_spend(tx: Transaction) -> str:
    """
    Last checks, then the raw transaction hex for ``sendrawtransaction``.

    Uses the library's own ``Transaction.serialize()`` and re-parses the result to make
    sure it round-trips.

    Raises:
        HashlockSpendSigningError: an input is still unsigned.
        HashlockError: empty tx, negative output, or serialisation does not round-trip.
    """
    if not tx.vin or not tx.vout:
        raise HashlockError("Transaction needs at least one input and one output")
    for i, txin in enumerate(tx.vin):
        if not txin.script_sig and not txin.witness:
            raise HashlockSpendSigningError(f"Input {i} is not signed")
    if any(out.value < 0 for out in tx.vout):
        raise HashlockError("Transaction has a negative output value")

    tx.has_witness = any(txin.witness for txin in tx.vin)
    raw = tx.serialize().hex()
    try:
        ok = parse_transaction(raw).txid() == tx.txid()
    except Exception as exc:
        raise HashlockError(f"Serialisation does not round-trip: {exc}") from exc
    if not ok:
        raise HashlockError("Serialisation does not round-trip (txid changed)")
    return raw


# ---------------------------------------------------------------------------
# One call: build + sign + finalize
# ---------------------------------------------------------------------------

def spend_hashlock(
    utxo: Mapping,
    private_key: bytes,
    destination: str,
    amount: Optional[int] = None,
    fee: Optional[int] = None,
    secret: Union[str, bytes, bytearray, None] = None,
    *,
    fee_rate: Optional[int] = None,
    change_address: Optional[str] = None,
) -> HashlockSpendResult:
    """Full spend of one C2 UTXO with an explicit private key. ``secret`` is required."""
    if secret is None:
        raise InvalidHashlockSecretError("secret is required to spend a HASHLOCK UTXO")
    u = normalize_hashlock_utxo(utxo)
    tx = build_hashlock_spend(
        utxo, destination, amount=amount, fee=fee, secret=secret,
        fee_rate=fee_rate, change_address=change_address,
    )
    sign_hashlock_input(tx, 0, utxo, private_key, secret)
    raw = finalize_hashlock_spend(tx)

    total_out = sum(o.value for o in tx.vout)
    sent = tx.vout[0].value
    change = total_out - sent
    return HashlockSpendResult(
        tx=tx,
        raw_transaction=raw,
        txid=tx.txid(),
        fee=u.value - total_out,
        amount=sent,
        change=change,
        secret_hash=u.secret_hash.hex(),
    )

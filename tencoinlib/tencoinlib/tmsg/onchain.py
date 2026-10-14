"""
On-chain TMSG: an encrypted message inside an OP_RETURN output.

Transaction layout::

    output 0   >= 1 Teno to the recipient address   (the dust limit does not apply)
    output 1   OP_RETURN  <TMSG payload>            (up to 1024 bytes of data)
    output 2   change back to the sender, if any

Capacity: 1024 - 66 = 958 plaintext bytes for one recipient (v1); with N recipients (v2)
the payload overhead is 34 + 93*N bytes (see ``tmsg.max_plaintext``).

Typical use::

    tx = tmsg.build_tmsg_transaction(
        utxos, "tc1q...recipient", "Hello!",
        recipients=recipient_pubkey,            # or None: look it up with rpc.get_public_key
        change_address="tc1q...me", rpc=rpc,
    )
    raw = tx.sign(my_private_keys).raw_transaction
    rpc.send_raw_transaction(raw)

    # reading
    for msg in tmsg.decrypt_transaction(txid, my_private_key, rpc=rpc):
        print(msg.text)

Sender inputs must be P2WPKH or P2PKH outputs (the keys are matched by HASH160).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from ..constants import (
    DUST_LIMIT,
    MIN_RELAY_FEE,
    OP_RETURN,
    OP_RETURN_MAX_DATA,
    OUTPUT_FLAG_RANGE,
    TMSG_MAGIC,
    TMSG_MIN_PAYMENT,
)
from ..transaction.address import AddressError, address_to_script, is_valid_address
from ..transaction.builder import TransactionBuilder, TransactionBuilderError
from ..transaction.core import Transaction, TxIn, TxOut, parse_transaction
from ..transaction.fee import FeeCalculator
from ..transaction.signer import LegacySigner, SegWitSigner, _push_data
from ..utils import hash160
from . import crypto
from .errors import TMSGDecryptionError, TMSGError, TMSGFormatError, TMSGKeyError, TMSGSizeError
from .keys import (
    PrivateKeyLike,
    PublicKeyLike,
    normalize_private_keys,
    parse_public_keys,
    public_key_from_private_key,
)

OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x4C, 0x4D, 0x4E


# ---------------------------------------------------------------------------
# OP_RETURN script helpers
# ---------------------------------------------------------------------------

def op_return_script_length(data_length: int) -> int:
    """Length of the OP_RETURN script that carries ``data_length`` data bytes."""
    if data_length == 0:
        return 1
    if data_length <= 0x4B:
        return 2 + data_length
    if data_length <= 0xFF:
        return 3 + data_length
    return 4 + data_length


def parse_op_return(script: bytes) -> Optional[bytes]:
    """
    Return the data pushed by an ``OP_RETURN <push>`` script, or None if ``script`` is not
    exactly one OP_RETURN followed by a single data push.
    """
    script = bytes(script)
    if not script or script[0] != OP_RETURN:
        return None
    if len(script) == 1:
        return b""
    op = script[1]
    if 1 <= op <= 0x4B:
        n, start = op, 2
    elif op == OP_PUSHDATA1 and len(script) >= 3:
        n, start = script[2], 3
    elif op == OP_PUSHDATA2 and len(script) >= 4:
        n, start = int.from_bytes(script[2:4], "little"), 4
    elif op == OP_PUSHDATA4 and len(script) >= 6:
        n, start = int.from_bytes(script[2:6], "little"), 6
    else:
        return None
    if start + n != len(script):
        return None
    return script[start:]


# ---------------------------------------------------------------------------
# UTXO handling
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Input:
    txid: str
    vout: int
    value: int
    script_pubkey: bytes
    kind: str                 # "p2wpkh" | "p2pkh"
    owner_hash: bytes


def _normalize_utxo(utxo: Mapping[str, Any]) -> _Input:
    if not isinstance(utxo, Mapping):
        raise TMSGError("each utxo must be a dict")
    txid = utxo.get("txid")
    vout = utxo.get("vout")
    value = utxo.get("amount", utxo.get("value"))
    script = None
    for key in ("script_pubkey", "scriptPubKey", "scriptpubkey"):
        if utxo.get(key) is not None:
            script = utxo[key]
            break
    if not isinstance(txid, str) or len(txid) != 64:
        raise TMSGError(f"invalid utxo txid: {txid!r}")
    if isinstance(vout, bool) or not isinstance(vout, int) or vout < 0:
        raise TMSGError(f"invalid utxo vout: {vout!r}")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TMSGError(f"invalid utxo amount (Tenos): {value!r}")
    if isinstance(script, str):
        try:
            script = bytes.fromhex(script)
        except ValueError:
            raise TMSGError("utxo script_pubkey is not valid hex") from None
    if not isinstance(script, (bytes, bytearray)):
        raise TMSGError("utxo has no script_pubkey / scriptPubKey")
    script = bytes(script)

    if len(script) == 22 and script[:2] == b"\x00\x14":
        return _Input(txid.lower(), vout, value, script, "p2wpkh", script[2:])
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac":
        return _Input(txid.lower(), vout, value, script, "p2pkh", script[3:23])
    raise TMSGError(
        f"unsupported input {txid}:{vout}: only P2WPKH and P2PKH outputs can fund a TMSG here"
    )


def _dummy_unlock(kind: str) -> Tuple[bytes, List[bytes]]:
    sig, pub = b"\x00" * 73, b"\x00" * 33
    if kind == "p2wpkh":
        return b"", [sig, pub]
    return _push_data(sig) + _push_data(pub), []


def _estimate_fee(inputs: Sequence[_Input], outputs: Sequence[TxOut], rate: int) -> int:
    vin = []
    for inp in inputs:
        script_sig, witness = _dummy_unlock(inp.kind)
        vin.append(TxIn(inp.txid, inp.vout, script_sig=script_sig, witness=witness))
    size = Transaction(version=1, vin=vin, vout=list(outputs)).calculate_vsize()
    return max(size * rate, MIN_RELAY_FEE)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class TMSGTransaction:
    """A TMSG transaction and what it contains. Call ``sign()`` before broadcasting."""

    tx: Transaction
    payload: bytes                  # the TMSG payload inside the OP_RETURN
    recipients: List[bytes]         # public keys the message is encrypted to
    version: int                    # TMSG version (1 or 2)
    fee: int                        # Tenos
    amount: int                     # Tenos paid to the recipient (output 0)
    change: int                     # Tenos returned to the sender (output 2), 0 if none
    plaintext_size: int             # bytes of message actually encrypted (after any padding)
    padding: int = 0                # spaces appended to avoid an unsafe size
    signed: bool = False
    broadcast_txid: Optional[str] = None     # set when sent through Wallet.send_tmsg(broadcast=True)
    _inputs: List[_Input] = field(default_factory=list, repr=False)

    @property
    def txid(self) -> str:
        """Transaction id (final only after signing for legacy P2PKH inputs)."""
        return self.tx.txid()

    @property
    def raw_transaction(self) -> str:
        """Hex for ``send_raw_transaction``. Only available after ``sign()``."""
        if not self.signed:
            raise TMSGError("transaction is not signed: call .sign(private_keys) first")
        return self.tx.serialize().hex()

    def sign(self, private_keys: Union[PrivateKeyLike, Iterable[PrivateKeyLike]]) -> "TMSGTransaction":
        """
        Sign every input. ``private_keys`` is a pool: each input uses the key whose
        HASH160 matches its output script.

        Raises:
            TMSGKeyError: some input has no matching key.
        """
        pool = {}
        for key in normalize_private_keys(private_keys):
            pool[hash160(public_key_from_private_key(key))] = key
        keys = []
        for i, inp in enumerate(self._inputs):
            key = pool.get(inp.owner_hash)
            if key is None:
                raise TMSGKeyError(f"no private key matches input {i} ({inp.txid}:{inp.vout})")
            keys.append(key)

        for i, (inp, key) in enumerate(zip(self._inputs, keys)):
            if inp.kind == "p2wpkh":
                SegWitSigner.sign_p2wpkh_input(self.tx, i, {"value": inp.value}, key)
            else:
                LegacySigner.sign_p2pkh_input(self.tx, i, key, inp.script_pubkey)
        self.tx.has_witness = any(vin.witness for vin in self.tx.vin)
        self.signed = True
        return self


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

def _fit_plaintext(
    plaintext: bytes, recipients: int, version: Optional[int],
    size_policy: str, can_pad: bool,
) -> Tuple[bytes, int]:
    """Check the OP_RETURN limit and the unsafe-size window; return (plaintext, padding)."""
    ov = crypto.overhead(recipients, version)
    length = ov + len(plaintext)
    if length > OP_RETURN_MAX_DATA:
        raise TMSGSizeError(
            f"message of {len(plaintext)} bytes needs {length} payload bytes, but an OP_RETURN "
            f"carries at most {OP_RETURN_MAX_DATA}; with {recipients} recipient(s) the maximum "
            f"message size is {crypto.max_plaintext(recipients, version)} bytes",
            size=length, limit=OP_RETURN_MAX_DATA,
        )
    script_len = op_return_script_length(length)
    if script_len not in OUTPUT_FLAG_RANGE:
        return plaintext, 0

    pad = OUTPUT_FLAG_RANGE[-1] + 1 - script_len          # first length outside the flag range
    trim = script_len - (OUTPUT_FLAG_RANGE[0] - 1)
    if size_policy == "pad" and can_pad and length + pad <= OP_RETURN_MAX_DATA:
        return plaintext + b" " * pad, pad
    raise TMSGSizeError(
        f"a message of {len(plaintext)} bytes gives a {script_len}-byte OP_RETURN script, which "
        f"nodes cannot tell apart from a conditional-output flag. Make the message {pad} byte(s) "
        f"longer or {trim} byte(s) shorter"
        + (", or pass size_policy='pad' to append spaces automatically" if can_pad else ""),
        size=length, pad_bytes=pad,
    )


def build_tmsg_transaction(
    utxos: Sequence[Mapping[str, Any]],
    to_address: str,
    message: Union[str, bytes],
    recipients: Union[None, PublicKeyLike, Iterable[PublicKeyLike]] = None,
    *,
    amount: int = TMSG_MIN_PAYMENT,
    fee: Optional[int] = None,
    fee_rate: Optional[int] = None,
    change_address: Optional[str] = None,
    rpc: Any = None,
    select: bool = True,
    size_policy: str = "error",
    version: Optional[int] = None,
) -> TMSGTransaction:
    """
    Build an (unsigned) on-chain TMSG transaction.

    Args:
        utxos:          spendable outputs, as returned by ``rpc.list_unspent`` (``txid``, ``vout``,
                        ``amount``, ``scriptPubKey``). Only P2WPKH / P2PKH are supported.
        to_address:     recipient; output 0 pays them ``amount`` Tenos.
        message:        text (UTF-8) or bytes to encrypt.
        recipients:     who can decrypt: a public key (hex / bytes), a list of them (v2, any one
                        key opens it), or addresses (with ``rpc``). None = the key of ``to_address``,
                        looked up on-chain with ``rpc.get_public_key``.
        amount:         Tenos for the recipient, default 1 (the minimum). The dust limit does not
                        apply to TMSG transactions.
        fee, fee_rate:  exact fee in Tenos, or Tenos per vbyte (default FeeCalculator.DEFAULT_FEE_RATE;
                        never below MIN_RELAY_FEE). The estimate includes the signatures.
        change_address: where the rest goes. Required when at least DUST_LIMIT would be left
                        over (otherwise it would be burned as fee).
        rpc:            RPCClient, only needed to resolve addresses / the default recipient key.
        select:         True = spend the fewest, largest UTXOs that cover the cost;
                        False = spend every UTXO given.
        size_policy:    some payload sizes (190..204 bytes) cannot be parsed safely by nodes.
                        "error" (default) raises TMSGSizeError; "pad" appends spaces to a text
                        message to reach a safe size.
        version:        None = automatic (1 key -> v1, 2+ -> v2).

    Returns:
        TMSGTransaction; call ``.sign(private_keys)`` then use ``.raw_transaction``.

    Raises:
        TMSGSizeError, TMSGKeyError, TMSGError, PublicKeyNotFoundError
    """
    if size_policy not in ("error", "pad"):
        raise ValueError("size_policy must be 'error' or 'pad'")
    if not isinstance(to_address, str) or not is_valid_address(to_address):
        raise TMSGError(f"invalid recipient address: {to_address!r}")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < TMSG_MIN_PAYMENT:
        raise TMSGError(f"amount must be an integer >= {TMSG_MIN_PAYMENT} Teno, got {amount!r}")
    if change_address is not None and not is_valid_address(change_address):
        raise TMSGError(f"invalid change address: {change_address!r}")
    for name, value in (("fee", fee), ("fee_rate", fee_rate)):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise TMSGError(f"{name} must be a non-negative integer, got {value!r}")
    if not utxos:
        raise TMSGError("no UTXOs given")

    # --- message -> payload ----------------------------------------------------------
    is_text = isinstance(message, str)
    if is_text:
        plaintext = message.encode("utf-8")
    elif isinstance(message, (bytes, bytearray)):
        plaintext = bytes(message)
    else:
        raise TMSGError(f"message must be str or bytes, got {type(message).__name__}")
    if not plaintext:
        raise TMSGError("message is empty")

    if recipients is None:
        if rpc is None:
            raise TMSGKeyError(
                "no recipients given: pass recipients=<public key>, or rpc= to look up the key of "
                "to_address on-chain"
            )
        recipients = to_address
    keys = parse_public_keys(recipients, rpc=rpc)

    plaintext, padding = _fit_plaintext(plaintext, len(keys), version, size_policy, is_text)
    payload = crypto.encrypt(plaintext, keys, version=version)
    info = crypto.inspect(payload)

    # --- inputs, fee, change ---------------------------------------------------------------
    candidates = [_normalize_utxo(u) for u in utxos]
    rate = FeeCalculator.DEFAULT_FEE_RATE if fee_rate is None else fee_rate
    dest_script = address_to_script(to_address)
    opret_script = TransactionBuilder()._build_op_return_script(payload)   # same encoder the builder uses
    change_script = address_to_script(change_address) if change_address else None

    def outputs(with_change: bool) -> List[TxOut]:
        outs = [TxOut(amount, dest_script), TxOut(0, opret_script)]
        if with_change and change_script:
            outs.append(TxOut(DUST_LIMIT, change_script))
        return outs

    def fee_for(chosen: Sequence[_Input], with_change: bool) -> int:
        return fee if fee is not None else _estimate_fee(chosen, outputs(with_change), rate)

    if select:
        chosen: List[_Input] = []
        total = 0
        for cand in sorted(candidates, key=lambda c: c.value, reverse=True):
            chosen.append(cand)
            total += cand.value
            if total >= amount + fee_for(chosen, True):
                break
        else:
            raise TMSGError(
                f"insufficient funds: {total} Tenos available, need {amount} + fee "
                f"{fee_for(chosen, True)}"
            )
    else:
        chosen = candidates
        total = sum(c.value for c in chosen)

    fee_no_change = fee_for(chosen, False)
    remaining = total - amount - fee_no_change
    if remaining < 0:
        raise TMSGError(f"insufficient funds: have {total}, need {amount + fee_no_change}")

    use_change = False
    final_fee = total - amount                 # default: everything left goes to the miner
    if remaining >= DUST_LIMIT:
        if not change_address:
            raise TMSGError(
                f"{remaining} Tenos would be burned as extra fee: pass change_address "
                "(or use fee= to set the fee yourself and select=True to spend fewer UTXOs)"
            )
        fee_with_change = fee_for(chosen, True)
        if total - amount - fee_with_change >= DUST_LIMIT:
            use_change, final_fee = True, fee_with_change

    # --- assemble with the standard builder ---------------------------------------------------
    try:
        builder = TransactionBuilder()
        for inp in chosen:
            builder.add_input(inp.txid, inp.vout, inp.value, inp.script_pubkey)
        builder.add_tmsg_output(to_address, payload, amount)
        if use_change:
            builder.set_change_address(change_address)
        builder.set_fee(final_fee)
        builder.set_segwit(any(i.kind == "p2wpkh" for i in chosen))
        tx, actual_fee = builder.build()
    except TransactionBuilderError as exc:
        raise TMSGError(str(exc)) from exc

    return TMSGTransaction(
        tx=tx, payload=payload, recipients=keys, version=info.version,
        fee=actual_fee, amount=amount, change=tx.vout[2].value if len(tx.vout) > 2 else 0,
        plaintext_size=len(plaintext), padding=padding, _inputs=list(chosen),
    )


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OnChainTMSG:
    output_index: int
    payload: bytes


@dataclass(frozen=True)
class DecryptedMessage:
    output_index: int
    plaintext: bytes

    @property
    def text(self) -> str:
        try:
            return self.plaintext.decode("utf-8")
        except UnicodeDecodeError:
            raise TMSGFormatError("the message is not UTF-8 text; use .plaintext") from None


def _as_transaction(source: Union[Transaction, str, bytes], rpc: Any = None) -> Transaction:
    if isinstance(source, Transaction):
        return source
    if isinstance(source, (bytes, bytearray)):
        source = bytes(source).hex()
    if not isinstance(source, str):
        raise TMSGFormatError(f"expected a Transaction, raw hex or txid, got {type(source).__name__}")
    text = source.strip()
    if len(text) == 64:                                    # a txid
        if rpc is None:
            raise TMSGError("a txid needs rpc= to fetch the transaction")
        text = rpc.get_raw_transaction(text)
        if not text:
            raise TMSGError("the node returned no raw transaction for this txid")
    try:
        return parse_transaction(text)
    except Exception as exc:
        raise TMSGFormatError(f"cannot parse the transaction: {exc}") from exc


def extract_tmsg_payloads(source: Union[Transaction, str, bytes], *, rpc: Any = None) -> List[OnChainTMSG]:
    """
    Find the TMSG payloads of a transaction (Transaction, raw hex, or txid with ``rpc``).

    An output counts when its script is ``OP_RETURN <single push>`` and the data starts with
    ``TMSG``. The structure of each payload is validated (``tmsg.inspect``).
    """
    tx = _as_transaction(source, rpc)
    found = []
    for index, out in enumerate(tx.vout):
        data = parse_op_return(out.script_pubkey)
        if data and data[:4] == TMSG_MAGIC:
            crypto.inspect(data)
            found.append(OnChainTMSG(index, data))
    return found


def decrypt_transaction(
    source: Union[Transaction, str, bytes],
    private_keys: Union[PrivateKeyLike, Iterable[PrivateKeyLike]],
    *,
    rpc: Any = None,
) -> List[DecryptedMessage]:
    """
    Decrypt the TMSG(s) of a transaction with one or more private keys.

    Returns the messages that one of the keys opens.

    Raises:
        TMSGFormatError:     the transaction contains no TMSG.
        TMSGDecryptionError: it contains TMSGs, but none of the keys opens any.
    """
    payloads = extract_tmsg_payloads(source, rpc=rpc)
    if not payloads:
        raise TMSGFormatError("the transaction contains no TMSG output")
    keys = normalize_private_keys(private_keys)
    messages = []
    for item in payloads:
        try:
            messages.append(DecryptedMessage(item.output_index, crypto.decrypt(item.payload, keys)))
        except TMSGDecryptionError:
            continue
    if not messages:
        raise TMSGDecryptionError("none of the given private keys opens a message in this transaction")
    return messages

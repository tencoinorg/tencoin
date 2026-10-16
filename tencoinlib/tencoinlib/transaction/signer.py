import struct
from typing import List, Optional, Union
from ..utils import sha256d, hash160, encode_varint
from .core import Transaction, TxIn, TxOut
from .address import decode_address
from .script import build_p2pkh_script


class SigningError(Exception):
    pass


# ---------------------------------------------------------------------------
# Script push helpers
# ---------------------------------------------------------------------------

def _key_bytes(key) -> bytes:
    """A private key given as bytes, hex or WIF (compressed or uncompressed) -> 32 bytes."""
    if isinstance(key, (bytes, bytearray)):
        return bytes(key)
    if isinstance(key, str):
        from ..keys.wif import WIFError, to_private_key_bytes
        try:
            return to_private_key_bytes(key)
        except WIFError as exc:
            raise SigningError(str(exc)) from exc
    raise SigningError(f"private key must be bytes, hex or WIF, got {type(key).__name__}")


def _push_data(data: bytes) -> bytes:
    """
    Encode a data push for use inside a scriptSig (Bitcoin Script rules).

    Unlike encode_varint (which is for transaction-level length prefixes),
    Script push opcodes follow different rules:
        <= 75 bytes  : single length byte
        76..255 bytes: OP_PUSHDATA1 (0x4c) + 1-byte length
        256..65535   : OP_PUSHDATA2 (0x4d) + 2-byte LE length
        > 65535      : OP_PUSHDATA4 (0x4e) + 4-byte LE length

    This matters for redeem scripts in P2SH multisig with n >= 3, where the
    redeem script exceeds 75 bytes and requires the PUSHDATA1 opcode.
    """
    ln = len(data)
    if ln <= 0x4b:
        return bytes([ln]) + data
    elif ln <= 0xff:
        return b'\x4c' + bytes([ln]) + data
    elif ln <= 0xffff:
        return b'\x4d' + struct.pack("<H", ln) + data
    else:
        return b'\x4e' + struct.pack("<I", ln) + data


# ---------------------------------------------------------------------------
# Key normalisation helper
# ---------------------------------------------------------------------------

# Type alias: one input's keys — either a single key or a list of keys.
# List[bytes]           → multiple keys for one input (multisig)
# bytes                 → single key for one input
_KeysForInput = Union[bytes, List[bytes]]


def _normalise_keys(
    private_keys: Union[List[_KeysForInput], List[bytes]],
) -> List[List[bytes]]:
    """
    Normalise the private_keys argument accepted by every sign_transaction.

    Accepted shapes (all produce List[List[bytes]] internally):

    1. Flat list of single keys — one key per input (original API, single-sig):
           [key_a, key_b, key_c]
           → [[key_a], [key_b], [key_c]]

    2. Nested list — one list of keys per input (multisig-friendly):
           [[key_a1, key_a2], [key_b1], [key_b2, key_b3]]
           → [[key_a1, key_a2], [key_b1], [key_b2, key_b3]]

    3. Mixed — some inputs have one key, others have multiple:
           [key_a, [key_b1, key_b2], key_c]
           → [[key_a], [key_b1, key_b2], [key_c]]

    Every key may be raw bytes, a 64-char hex string, or a WIF string; the form
    (and, for a WIF, compressed/uncompressed) is detected automatically.

    The first key in each sub-list is the "primary" key passed to legacy
    single-sig helpers; all keys in the sub-list are available for multisig.
    cosigner_keys in utxo dicts are MERGED with the keys provided here, so
    you can supply them either way (or both).
    """
    result: List[List[bytes]] = []
    for item in private_keys:
        if isinstance(item, (bytes, bytearray, str)):
            result.append([_key_bytes(item)])
        elif isinstance(item, list):
            if not item:
                raise SigningError("Empty key list for an input is not allowed")
            result.append([_key_bytes(k) for k in item])
        else:
            raise SigningError(
                f"private_keys must contain bytes or List[bytes], got {type(item)}"
            )
    return result


# ---------------------------------------------------------------------------
# Internal multisig helpers
# ---------------------------------------------------------------------------

def _parse_multisig_script(redeem_script: bytes):
    """
    Parse an m-of-n multisig redeem/witness script and return (m, pubkeys).

    Expected format:
        OP_m <len pk1> <pk1> ... <len pkn> <pkn> OP_n OP_CHECKMULTISIG

    Raises SigningError if the script is not a valid multisig script.
    """
    if len(redeem_script) < 3:
        raise SigningError("Script too short to be multisig")

    first = redeem_script[0]
    last = redeem_script[-1]
    second_last = redeem_script[-2]

    if last != 0xAE:
        raise SigningError("Script does not end with OP_CHECKMULTISIG")

    if not (0x51 <= first <= 0x60):
        raise SigningError(f"Invalid OP_m byte: 0x{first:02x}")
    m = first - 0x50

    if not (0x51 <= second_last <= 0x60):
        raise SigningError(f"Invalid OP_n byte: 0x{second_last:02x}")
    n = second_last - 0x50

    if m > n:
        raise SigningError(f"m={m} > n={n} in multisig script")

    pubkeys = []
    offset = 1
    for _ in range(n):
        if offset >= len(redeem_script) - 2:
            raise SigningError("Script truncated while reading pubkeys")
        pk_len = redeem_script[offset]
        offset += 1
        if pk_len not in (33, 65):
            raise SigningError(f"Unexpected pubkey length {pk_len} in multisig script")
        pubkeys.append(redeem_script[offset: offset + pk_len])
        offset += pk_len

    if len(pubkeys) != n:
        raise SigningError(f"Expected {n} pubkeys, got {len(pubkeys)}")

    return m, pubkeys


def _is_multisig_script(redeem_script: bytes) -> bool:
    try:
        _parse_multisig_script(redeem_script)
        return True
    except SigningError:
        return False


def _collect_keys_for_multisig(
    keys_for_input: List[bytes],
    utxo: dict,
) -> List[bytes]:
    """
    Merge keys provided via private_keys argument with utxo['cosigner_keys'].
    Deduplicates by pubkey so the same key is never used twice.
    """
    from ..keys.ec import privkey_to_pubkey

    all_keys = list(keys_for_input) + list(utxo.get("cosigner_keys", []))

    seen = {}
    for k in all_keys:
        pub = privkey_to_pubkey(k, compressed=True)
        if pub not in seen:
            seen[pub] = k
    return list(seen.values())


def _sign_multisig(
    private_keys_for_input: List[bytes],
    digest: bytes,
    redeem_script: bytes,
) -> List[bytes]:
    """
    Produce the ordered list of DER signatures (with sighash byte) for a
    multisig input.  Signatures are in the same order as the corresponding
    pubkeys appear in the redeem script (canonical BIP-11 order).
    """
    from ..keys.ec import sign, privkey_to_pubkey

    m, script_pubkeys = _parse_multisig_script(redeem_script)

    pk_map = {}
    for priv in private_keys_for_input:
        pub = privkey_to_pubkey(priv, compressed=True)
        pk_map[pub] = priv

    sighash_type = 1  # SIGHASH_ALL
    signatures = []
    for pub in script_pubkeys:
        if pub in pk_map:
            sig = sign(pk_map[pub], digest)
            signatures.append(sig + bytes([sighash_type]))

    if len(signatures) < m:
        raise SigningError(
            f"multisig requires {m} signatures but only {len(signatures)} "
            f"matching private keys provided"
        )

    return signatures[:m]


# ---------------------------------------------------------------------------
# SegWitSigner
# ---------------------------------------------------------------------------

def _p2pkh_public_key(private_key: bytes, script: bytes) -> bytes:
    """
    Public key to reveal for a P2PKH-style script (``76 a9 14 <hash160> 88 ac``).

    Compressed by default; the uncompressed form when the script's hash is that of the
    uncompressed key. Any other script keeps the historical behaviour (compressed).
    """
    from ..keys.ec import privkey_to_pubkey
    from ..keys.pubkey import public_key_for_hash160

    script = bytes(script)
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[23:] == b"\x88\xac":
        match = public_key_for_hash160(private_key, script[3:23])
        if match is not None:
            return match
    return privkey_to_pubkey(private_key, compressed=True)


class SegWitSigner:
    """
    Signs P2WPKH and P2WSH inputs (BIP-143).

    UTXO dict fields:
        address        : str        — spending address (tc1q...)
        value          : int        — UTXO value in Tenos
        For P2WSH only:
        witness_script : bytes      — the witness script (e.g. multisig)
        cosigner_keys  : List[bytes]— extra private keys (merged with
                          whatever is passed in private_keys)

    private_keys argument to sign_transaction accepts:
        [key]                          single-sig, one key per input
        [[key1, key2], [key3], ...]    multisig, one list per input
        [key, [key1, key2], key, ...]  mixed
    """

    @staticmethod
    def create_witness_signature(
        tx: Transaction,
        input_index: int,
        private_key: bytes,
        script_code: bytes,
        value: int,
        sighash_type: int = 1,
    ) -> bytes:
        try:
            private_key = _key_bytes(private_key)
            digest = SegWitSigner.bip143_digest(
                tx, input_index, script_code, value, sighash_type
            )
            from ..keys.ec import sign
            return sign(private_key, digest) + bytes([sighash_type])
        except Exception as e:
            raise SigningError(f"Failed to create witness signature: {e}")

    @staticmethod
    def bip143_digest(
        tx: Transaction,
        input_index: int,
        script_code: bytes,
        value: int,
        sighash_type: int = 1,
    ) -> bytes:
        prevouts = b""
        for txin in tx.vin:
            prevouts += bytes.fromhex(txin.prev_txid)[::-1] + struct.pack("<I", txin.vout)
        hashPrevouts = sha256d(prevouts)

        sequences = b"".join(struct.pack("<I", txin.sequence) for txin in tx.vin)
        hashSequence = sha256d(sequences)

        outputs = b"".join(txout.serialize() for txout in tx.vout)
        hashOutputs = sha256d(outputs)

        txin = tx.vin[input_index]
        digest = struct.pack("<I", tx.version)
        digest += hashPrevouts
        digest += hashSequence
        digest += bytes.fromhex(txin.prev_txid)[::-1]
        digest += struct.pack("<I", txin.vout)
        digest += encode_varint(len(script_code))
        digest += script_code
        digest += struct.pack("<Q", value)
        digest += struct.pack("<I", txin.sequence)
        digest += hashOutputs
        digest += struct.pack("<I", tx.locktime)
        digest += struct.pack("<I", sighash_type)

        return sha256d(digest)

    # ------------------------------------------------------------------
    # P2WPKH (single-sig native SegWit)
    # ------------------------------------------------------------------

    @staticmethod
    def sign_p2wpkh_input(
        tx: Transaction,
        input_index: int,
        utxo: dict,
        private_key: bytes,
    ):
        """Sign a P2WPKH input. Sets witness = [sig, pubkey]. The key may be bytes, hex or WIF."""
        from ..keys.ec import privkey_to_pubkey

        private_key = _key_bytes(private_key)
        public_key = privkey_to_pubkey(private_key, compressed=True)
        pubkey_hash = hash160(public_key)
        script_code = bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])

        signature = SegWitSigner.create_witness_signature(
            tx, input_index, private_key, script_code, utxo["value"]
        )

        tx.vin[input_index].witness = [signature, public_key]
        tx.vin[input_index].script_sig = b""
        tx.has_witness = True

    # Backward-compatible alias
    @staticmethod
    def sign_input(
        tx: Transaction,
        input_index: int,
        utxo: dict,
        private_key: bytes,
    ):
        """Backward-compatible alias — signs a P2WPKH input."""
        SegWitSigner.sign_p2wpkh_input(tx, input_index, utxo, private_key)

    # ------------------------------------------------------------------
    # P2WSH (script-hash native SegWit — includes multisig)
    # ------------------------------------------------------------------

    @staticmethod
    def sign_p2wsh_input(
        tx: Transaction,
        input_index: int,
        utxo: dict,
        keys_for_input: List[bytes],
    ):
        """
        Sign a P2WSH input.

        keys_for_input  : all private keys available for this input.
                          For single-sig pass [key]; for multisig pass
                          all m (or more) matching keys.
        utxo must contain:
            witness_script : bytes
        utxo may contain:
            cosigner_keys  : List[bytes]  (merged with keys_for_input)

        Witness stack produced:
            multisig  → [b"", sig1, sig2, ..., witness_script]
            single-sig→ [sig, pubkey, witness_script]
        """
        if "witness_script" not in utxo:
            raise SigningError("P2WSH input UTXO must contain 'witness_script'")

        witness_script: bytes = utxo["witness_script"]
        script_code = witness_script

        if _is_multisig_script(witness_script):
            all_keys = _collect_keys_for_multisig(keys_for_input, utxo)
            digest = SegWitSigner.bip143_digest(
                tx, input_index, script_code, utxo["value"]
            )
            signatures = _sign_multisig(all_keys, digest, witness_script)
            tx.vin[input_index].witness = [b""] + signatures + [witness_script]
        else:
            # Single-sig P2WSH — use the first key
            primary_key = keys_for_input[0]
            signature = SegWitSigner.create_witness_signature(
                tx, input_index, primary_key, script_code, utxo["value"]
            )
            from ..keys.ec import privkey_to_pubkey
            public_key = privkey_to_pubkey(primary_key, compressed=True)
            tx.vin[input_index].witness = [signature, public_key, witness_script]

        tx.vin[input_index].script_sig = b""
        tx.has_witness = True

    # ------------------------------------------------------------------
    # Batch helpers
    # ------------------------------------------------------------------

    @staticmethod
    def sign_transaction(
        tx: Transaction,
        utxos: List[dict],
        private_keys: Union[List[_KeysForInput], List[bytes]],
    ) -> Transaction:
        """
        Sign all inputs as P2WPKH or P2WSH (auto-detected from utxo["address"]).

        private_keys accepts three shapes:
            [key_a, key_b]               one key per input  (single-sig)
            [[key_a1, key_a2], [key_b1]] one list per input (multisig)
            [key_a, [key_b1, key_b2]]    mixed

        For P2WSH multisig, cosigner_keys in each utxo dict are merged
        automatically with the keys provided here.
        """
        if len(tx.vin) != len(utxos):
            raise SigningError(
                f"Transaction has {len(tx.vin)} inputs but {len(utxos)} UTXOs provided"
            )
        if len(tx.vin) != len(private_keys):
            raise SigningError(
                f"Transaction has {len(tx.vin)} inputs but {len(private_keys)} key entries provided"
            )

        normalised = _normalise_keys(private_keys)

        signed_tx = Transaction(
            version=tx.version,
            vin=[
                TxIn(
                    prev_txid=txin.prev_txid,
                    vout=txin.vout,
                    script_sig=txin.script_sig,
                    sequence=txin.sequence,
                )
                for txin in tx.vin
            ],
            vout=tx.vout[:],
            locktime=tx.locktime,
        )
        signed_tx.has_witness = True

        for i in range(len(signed_tx.vin)):
            try:
                utxo = utxos[i]
                addr_type, _ = decode_address(utxo["address"])
                keys = normalised[i]

                if addr_type == "p2wpkh":
                    SegWitSigner.sign_p2wpkh_input(signed_tx, i, utxo, keys[0])
                elif addr_type == "p2wsh":
                    SegWitSigner.sign_p2wsh_input(signed_tx, i, utxo, keys)
                else:
                    raise SigningError(
                        f"UTXO {i} has unsupported address type for SegWitSigner: {addr_type}"
                    )
            except SigningError:
                raise
            except Exception as e:
                raise SigningError(f"Failed to sign input {i}: {e}")

        return signed_tx

    # ------------------------------------------------------------------
    # Verification helpers
    # ------------------------------------------------------------------

    @staticmethod
    def verify_witness(
        tx: Transaction,
        input_index: int,
        public_key: bytes,
        script_code: bytes,
        value: int,
        witness: List[bytes],
    ) -> bool:
        """Verify a P2WPKH witness (single-sig)."""
        if len(witness) < 2:
            return False

        signature = witness[0]
        witness_pubkey = witness[1]

        if witness_pubkey != public_key:
            return False
        if len(signature) < 1:
            return False

        sighash_type = signature[-1]
        signature_der = signature[:-1]

        digest = SegWitSigner.bip143_digest(
            tx, input_index, script_code, value, sighash_type
        )

        from ..keys.ec import verify
        return verify(public_key, digest, signature_der)


# ---------------------------------------------------------------------------
# LegacySigner
# ---------------------------------------------------------------------------

class LegacySigner:
    """
    Signs P2PKH and P2SH inputs (legacy serialization).

    private_keys argument to sign_transaction accepts the same three shapes
    as SegWitSigner.sign_transaction (flat, nested, or mixed).

    P2SH UTXO dict fields:
        address       : str         — spending address (M...)
        script_pubkey : bytes       — the on-chain scriptPubKey
        redeem_script : bytes       — the redeem script
        cosigner_keys : List[bytes] — extra private keys merged automatically
    """

    @staticmethod
    def legacy_digest(
        tx: Transaction,
        input_index: int,
        script_code: bytes,
        sighash_type: int = 1,
    ) -> bytes:
        if sighash_type != 1:
            raise SigningError(f"Only SIGHASH_ALL (1) is supported, got {sighash_type}")

        def le32(v: int) -> bytes:
            return struct.pack("<I", v)

        digest = le32(tx.version)
        digest += encode_varint(len(tx.vin))

        for i, txin in enumerate(tx.vin):
            prev_txid_bytes = bytes.fromhex(txin.prev_txid)[::-1]
            digest += prev_txid_bytes
            digest += le32(txin.vout)
            if i == input_index:
                digest += encode_varint(len(script_code))
                digest += script_code
            else:
                digest += encode_varint(0)
            digest += le32(txin.sequence)

        digest += encode_varint(len(tx.vout))
        for txout in tx.vout:
            digest += txout.serialize()

        digest += le32(tx.locktime)
        digest += le32(sighash_type)

        return sha256d(digest)

    @staticmethod
    def sign_p2pkh_input(
        tx: Transaction,
        input_index: int,
        private_key: bytes,
        script_pubkey: bytes,
        sighash_type: int = 1,
    ):
        """
        Sign a P2PKH input. scriptSig = <sig> <pubkey>.

        The pubkey is the compressed one, unless the script commits to the hash of the
        UNCOMPRESSED public key of this private key (legacy addresses): then that form is used.
        The key may be bytes, hex or WIF; its compression flag does not matter, the script decides.
        """
        from ..keys.ec import sign

        private_key = _key_bytes(private_key)
        public_key = _p2pkh_public_key(private_key, script_pubkey)
        digest = LegacySigner.legacy_digest(tx, input_index, script_pubkey, sighash_type)
        signature = sign(private_key, digest) + bytes([sighash_type])

        tx.vin[input_index].script_sig = _push_data(signature) + _push_data(public_key)

    @staticmethod
    def sign_p2sh_singlesig_input(
        tx: Transaction,
        input_index: int,
        private_key: bytes,
        redeem_script: bytes,
        sighash_type: int = 1,
    ):
        """
        Sign a single-sig P2SH input (P2SH-P2PKH style).
        scriptSig = <sig> <pubkey> <redeem_script>
        """
        from ..keys.ec import sign

        private_key = _key_bytes(private_key)
        public_key = _p2pkh_public_key(private_key, redeem_script)
        digest = LegacySigner.legacy_digest(tx, input_index, redeem_script, sighash_type)
        signature = sign(private_key, digest) + bytes([sighash_type])

        tx.vin[input_index].script_sig = (
            _push_data(signature)
            + _push_data(public_key)
            + _push_data(redeem_script)
        )

    @staticmethod
    def sign_p2sh_multisig_input(
        tx: Transaction,
        input_index: int,
        private_keys_for_input: List[bytes],
        redeem_script: bytes,
        sighash_type: int = 1,
    ):
        """
        Sign a multisig P2SH input (BIP-11).
        scriptSig = OP_0 <sig1> <sig2> ... <redeem_script>

        private_keys_for_input must contain at least m keys matching pubkeys
        in the redeem script.
        """
        private_keys_for_input = [_key_bytes(k) for k in private_keys_for_input]
        digest = LegacySigner.legacy_digest(tx, input_index, redeem_script, sighash_type)
        signatures = _sign_multisig(private_keys_for_input, digest, redeem_script)

        script_sig = bytes([0x00])          # OP_0 — CHECKMULTISIG off-by-one
        for sig in signatures:
            script_sig += _push_data(sig)
        script_sig += _push_data(redeem_script)

        tx.vin[input_index].script_sig = script_sig

    @staticmethod
    def sign_p2sh_input(
        tx: Transaction,
        input_index: int,
        keys_for_input: List[bytes],
        redeem_script: bytes,
        script_pubkey: bytes,
        sighash_type: int = 1,
    ):
        """
        Unified P2SH input signer — auto-detects single-sig vs multisig.

        keys_for_input : all available private keys for this input.
                         cosigner_keys in utxo should be merged before calling.
        """
        if _is_multisig_script(redeem_script):
            LegacySigner.sign_p2sh_multisig_input(
                tx, input_index, keys_for_input, redeem_script, sighash_type
            )
        else:
            LegacySigner.sign_p2sh_singlesig_input(
                tx, input_index, keys_for_input[0], redeem_script, sighash_type
            )

    @staticmethod
    def sign_transaction(
        tx: Transaction,
        utxos: List[dict],
        private_keys: Union[List[_KeysForInput], List[bytes]],
    ) -> Transaction:
        """
        Sign all inputs as P2PKH or P2SH (auto-detected).

        private_keys accepts three shapes:
            [key_a, key_b]               one key per input  (single-sig)
            [[key_a1, key_a2], [key_b1]] one list per input (multisig)
            [key_a, [key_b1, key_b2]]    mixed

        For P2SH multisig, cosigner_keys in each utxo dict are merged
        automatically with the keys provided here.
        """
        if len(tx.vin) != len(utxos):
            raise SigningError(
                f"Transaction has {len(tx.vin)} inputs but {len(utxos)} UTXOs provided"
            )
        if len(tx.vin) != len(private_keys):
            raise SigningError(
                f"Transaction has {len(tx.vin)} inputs but {len(private_keys)} key entries provided"
            )

        normalised = _normalise_keys(private_keys)

        signed_tx = Transaction(
            version=tx.version,
            vin=[
                TxIn(
                    prev_txid=txin.prev_txid,
                    vout=txin.vout,
                    script_sig=txin.script_sig,
                    sequence=txin.sequence,
                )
                for txin in tx.vin
            ],
            vout=tx.vout[:],
            locktime=tx.locktime,
        )

        for i in range(len(signed_tx.vin)):
            try:
                utxo = utxos[i]
                addr_type, _ = decode_address(utxo["address"])
                keys = normalised[i]

                if addr_type == "p2pkh":
                    LegacySigner.sign_p2pkh_input(
                        signed_tx, i, keys[0], utxo["script_pubkey"]
                    )
                elif addr_type == "p2sh":
                    redeem_script = utxo.get("redeem_script")
                    if redeem_script is None:
                        from ..keys.ec import privkey_to_pubkey
                        pubkey = privkey_to_pubkey(keys[0], compressed=True)
                        redeem_script = build_p2pkh_script(pubkey)

                    all_keys = _collect_keys_for_multisig(keys, utxo)
                    LegacySigner.sign_p2sh_input(
                        signed_tx, i, all_keys, redeem_script, utxo["script_pubkey"]
                    )
                else:
                    raise SigningError(
                        f"Unsupported address type for LegacySigner: {addr_type}"
                    )
            except SigningError:
                raise
            except Exception as e:
                raise SigningError(f"Failed to sign input {i}: {e}")

        return signed_tx


# ---------------------------------------------------------------------------
# TransactionSigner  (unified dispatcher)
# ---------------------------------------------------------------------------

class TransactionSigner:
    """
    Auto-dispatch signer — handles P2WPKH, P2WSH, P2PKH, and P2SH in one call.

    private_keys accepts three shapes:
        [key_a, key_b]                 one key per input  (single-sig / old API)
        [[key_a1, key_a2], [key_b1]]   one list per input (multisig-friendly)
        [key_a, [key_b1, key_b2]]      mixed

    UTXO dict fields (by address type):
        All:
            address        : str
        P2PKH / P2SH:
            script_pubkey  : bytes
        P2SH:
            redeem_script  : bytes         (required; inferred for single-sig if absent)
            cosigner_keys  : List[bytes]   (merged with private_keys automatically)
        P2WPKH:
            value          : int
        P2WSH:
            value          : int
            witness_script : bytes         (required)
            cosigner_keys  : List[bytes]   (merged with private_keys automatically)
    """

    @staticmethod
    def sign_transaction(
        tx: Transaction,
        utxos: List[dict],
        private_keys: Union[List[_KeysForInput], List[bytes]],
    ) -> Transaction:
        if len(tx.vin) != len(utxos):
            raise SigningError(
                f"Transaction has {len(tx.vin)} inputs but {len(utxos)} UTXOs provided"
            )
        if len(tx.vin) != len(private_keys):
            raise SigningError(
                f"Transaction has {len(tx.vin)} inputs but {len(private_keys)} key entries provided"
            )

        normalised = _normalise_keys(private_keys)

        signed_tx = Transaction(
            version=tx.version,
            vin=[
                TxIn(
                    prev_txid=txin.prev_txid,
                    vout=txin.vout,
                    script_sig=txin.script_sig,
                    sequence=txin.sequence,
                )
                for txin in tx.vin
            ],
            vout=tx.vout[:],
            locktime=tx.locktime,
        )

        has_segwit = False

        for i in range(len(signed_tx.vin)):
            try:
                utxo = utxos[i]
                addr_type, _ = decode_address(utxo["address"])
                keys = normalised[i]

                if addr_type == "p2wpkh":
                    SegWitSigner.sign_p2wpkh_input(signed_tx, i, utxo, keys[0])
                    has_segwit = True

                elif addr_type == "p2wsh":
                    SegWitSigner.sign_p2wsh_input(signed_tx, i, utxo, keys)
                    has_segwit = True

                elif addr_type == "p2pkh":
                    LegacySigner.sign_p2pkh_input(
                        signed_tx, i, keys[0], utxo["script_pubkey"]
                    )

                elif addr_type == "p2sh":
                    redeem_script = utxo.get("redeem_script")
                    if redeem_script is None:
                        from ..keys.ec import privkey_to_pubkey
                        pubkey = privkey_to_pubkey(keys[0], compressed=True)
                        redeem_script = build_p2pkh_script(pubkey)

                    all_keys = _collect_keys_for_multisig(keys, utxo)
                    LegacySigner.sign_p2sh_input(
                        signed_tx, i, all_keys, redeem_script, utxo["script_pubkey"]
                    )

                else:
                    raise SigningError(f"Unsupported address type: {addr_type}")

            except SigningError:
                raise
            except Exception as e:
                raise SigningError(f"Failed to sign input {i}: {e}")

        if has_segwit:
            signed_tx.has_witness = True

        return signed_tx
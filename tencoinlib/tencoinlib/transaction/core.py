import struct
from typing import List, Optional
from ..utils import encode_varint, decode_varint, sha256d
from ..constants import (
    COND_FLAG_TIMELOCK,
    COND_FLAG_HASHLOCK,
    TIMELOCK_MODE_HEIGHT,
    TIMELOCK_MODE_TIMESTAMP,
    HASHLOCK_HASH_SIZE,
)


# ---------------------------------------------------------------------------
# TxIn
# ---------------------------------------------------------------------------

class TxIn:
    """Transaction input."""

    def __init__(
        self,
        prev_txid: str,
        vout: int,
        script_sig: bytes = b"",
        sequence: int = 0xffffffff,
        witness: Optional[List[bytes]] = None,
    ):
        """
        Args:
            prev_txid: Previous transaction ID (hex, big-endian).
            vout:      Output index in the previous transaction.
            script_sig: Unlocking script (empty for SegWit inputs before signing).
            sequence:  Sequence number.
            witness:   Witness stack items for SegWit inputs.
        """
        self.prev_txid  = prev_txid
        self.vout       = vout
        self.script_sig = script_sig
        self.sequence   = sequence
        self.witness    = witness or []

    def serialize(self) -> bytes:
        """Serialize the input (witness data is NOT included here)."""
        prev_txid_bytes = bytes.fromhex(self.prev_txid)[::-1]  # little-endian

        data  = prev_txid_bytes
        data += struct.pack("<I", self.vout)
        data += encode_varint(len(self.script_sig))
        data += self.script_sig
        data += struct.pack("<I", self.sequence)
        return data

    def __repr__(self) -> str:
        return f"TxIn({self.prev_txid[:16]}..., vout={self.vout})"


# ---------------------------------------------------------------------------
# TxOut  — standard (unmodified)
# ---------------------------------------------------------------------------

class TxOut:
    """
    Standard transaction output.

    On-chain layout:
        [value : 8 B little-endian]
        [script_len : varint]
        [script_pubkey : script_len B]

    This class is completely unchanged from the original implementation.
    Conditional outputs are represented by the TimelockTxOut (0xC1) and
    HashlockTxOut (0xC2) subclasses.
    """

    def __init__(self, value: int, script_pubkey: bytes):
        """
        Args:
            value:        Amount in Tenos (satoshi-equivalent).
            script_pubkey: Locking script bytes.
        """
        self.value        = value
        self.script_pubkey = script_pubkey

    def serialize(self) -> bytes:
        """Serialize to raw bytes (standard format)."""
        data  = struct.pack("<Q", self.value)
        data += encode_varint(len(self.script_pubkey))
        data += self.script_pubkey
        return data

    def is_timelock(self) -> bool:
        """Return True if this output is a TIMELOCK conditional output."""
        return False

    def is_hashlock(self) -> bool:
        """Return True if this output is a HASHLOCK conditional output."""
        return False

    def __repr__(self) -> str:
        return (
            f"TxOut({self.value} Tenos, "
            f"script={self.script_pubkey[:20].hex()}...)"
        )


# ---------------------------------------------------------------------------
# TimelockTxOut  — conditional TIMELOCK output (0xC1)
# ---------------------------------------------------------------------------

class TimelockTxOut(TxOut):
    """
    Conditional TIMELOCK output (flag byte 0xC1).

    On-chain layout:
        [value     : 8 B little-endian ]   ← same as TxOut
        [0xC1      : 1 B               ]   ← TIMELOCK sentinel
        [time_mode : 1 B               ]   ← 0x01 = height, 0x02 = timestamp
        [lock_time : 8 B little-endian ]   ← block height or Unix timestamp
        [script_len: varint            ]   ← same as TxOut from here on
        [script_pubkey : script_len B  ]

    The node reads the byte that immediately follows `value`:
      • 0xC1      → TIMELOCK conditional output  (this class)
      • 0xC2-0xCF → reserved / future flags      (node rejects tx)
      • anything else → standard varint for script_len (fully backward-compat)

    Attributes:
        time_mode (int): TIMELOCK_MODE_HEIGHT (0x01) or
                         TIMELOCK_MODE_TIMESTAMP (0x02).
        lock_time (int): Unsigned 64-bit lock value (block height or
                         Unix timestamp in seconds).
    """

    # Extra bytes written between value and script: flag(1) + mode(1) + lock(8)
    OVERHEAD_BYTES = 10

    def __init__(
        self,
        value: int,
        script_pubkey: bytes,
        time_mode: int,
        lock_time: int,
    ):
        """
        Args:
            value:        Amount in Tenos.
            script_pubkey: Recipient locking script.
            time_mode:    TIMELOCK_MODE_HEIGHT or TIMELOCK_MODE_TIMESTAMP.
            lock_time:    Block height or Unix timestamp (uint64).

        Raises:
            ValueError: If time_mode or lock_time are out of range.
        """
        if time_mode not in (TIMELOCK_MODE_HEIGHT, TIMELOCK_MODE_TIMESTAMP):
            raise ValueError(
                f"time_mode must be TIMELOCK_MODE_HEIGHT (0x01) or "
                f"TIMELOCK_MODE_TIMESTAMP (0x02), got 0x{time_mode:02x}"
            )
        if not (0 <= lock_time < 2 ** 64):
            raise ValueError(
                f"lock_time must be a 64-bit unsigned integer (0 … 2^64-1), "
                f"got {lock_time}"
            )

        super().__init__(value, script_pubkey)
        self.time_mode = time_mode
        self.lock_time = lock_time

    def serialize(self) -> bytes:
        """
        Serialize to raw bytes (TIMELOCK format).

        Layout: [value][0xC1][time_mode][lock_time][varint script_len][script]
        """
        data  = struct.pack("<Q", self.value)
        data += struct.pack("<B", COND_FLAG_TIMELOCK)
        data += struct.pack("<B", self.time_mode)
        data += struct.pack("<Q", self.lock_time)
        data += encode_varint(len(self.script_pubkey))
        data += self.script_pubkey
        return data

    def is_timelock(self) -> bool:
        return True

    def lock_mode_name(self) -> str:
        """Human-readable name for time_mode."""
        return (
            "block_height"
            if self.time_mode == TIMELOCK_MODE_HEIGHT
            else "unix_timestamp"
        )

    @property
    def lock_time_human(self) -> str:
        """
        Human-readable representation of lock_time.

        - TIMELOCK_MODE_HEIGHT    → plain integer        e.g. "200000"
        - TIMELOCK_MODE_TIMESTAMP → ISO-8601 UTC string  e.g. "2028-01-01 00:00:00 UTC"
        """
        if self.time_mode == TIMELOCK_MODE_TIMESTAMP:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(self.lock_time, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        return str(self.lock_time)

    def __repr__(self) -> str:
        return (
            f"TimelockTxOut({self.value} Tenos, "
            f"{self.lock_mode_name()}={self.lock_time_human}, "
            f"script={self.script_pubkey[:20].hex()}...)"
        )


# ---------------------------------------------------------------------------
# HashlockTxOut  — conditional HASHLOCK output (0xC2)
# ---------------------------------------------------------------------------

class HashlockTxOut(TxOut):
    """
    Conditional HASHLOCK output (flag byte 0xC2).

    Locks funds behind a secret: the output can only be spent by revealing
    a preimage whose SHA256 hash matches ``secret_hash``. This class only
    builds the LOCKING (creation) side of a HASHLOCK output. To SPEND one
    (preimage in witness/scriptSig) see transaction/hashlock.py
    (build_hashlock_spend, sign_hashlock_input, finalize_hashlock_spend).

    On-chain layout:
        [value       : 8 B little-endian ]   ← same as TxOut
        [0xC2        : 1 B               ]   ← HASHLOCK sentinel
        [secret_hash : 32 B              ]   ← SHA256(preimage), single round
        [script_len  : varint            ]   ← same as TxOut from here on
        [script_pubkey : script_len B    ]

    The node reads the byte that immediately follows `value`:
      • 0xC1      → TIMELOCK conditional output
      • 0xC2      → HASHLOCK conditional output  (this class)
      • 0xC3-0xCF → reserved / future flags      (node rejects tx)
      • anything else → standard varint for script_len (fully backward-compat)

    Attributes:
        secret_hash (bytes): SHA256(preimage), always exactly 32 bytes.
    """

    # Extra bytes written between value and script: flag(1) + secret_hash(32)
    OVERHEAD_BYTES = 33

    def __init__(
        self,
        value: int,
        script_pubkey: bytes,
        secret_hash: bytes,
    ):
        """
        Args:
            value:         Amount in Tenos.
            script_pubkey: Recipient locking script.
            secret_hash:   SHA256(preimage), exactly 32 bytes. This class
                           never derives the hash itself — callers compute
                           it (typically via hashlib.sha256(preimage).digest()
                           or TransactionBuilder.add_hashlock_output()).

        Raises:
            ValueError: If secret_hash is not exactly 32 bytes.
        """
        if not isinstance(secret_hash, (bytes, bytearray)) or len(secret_hash) != HASHLOCK_HASH_SIZE:
            raise ValueError(
                f"secret_hash must be exactly {HASHLOCK_HASH_SIZE} bytes, "
                f"got {len(secret_hash) if isinstance(secret_hash, (bytes, bytearray)) else type(secret_hash)}"
            )

        super().__init__(value, script_pubkey)
        self.secret_hash = bytes(secret_hash)

    def serialize(self) -> bytes:
        """
        Serialize to raw bytes (HASHLOCK format).

        Layout: [value][0xC2][secret_hash 32B][varint script_len][script]
        """
        data  = struct.pack("<Q", self.value)
        data += struct.pack("<B", COND_FLAG_HASHLOCK)
        data += self.secret_hash
        data += encode_varint(len(self.script_pubkey))
        data += self.script_pubkey
        return data

    def is_hashlock(self) -> bool:
        return True

    def __repr__(self) -> str:
        return (
            f"HashlockTxOut({self.value} Tenos, "
            f"secret_hash={self.secret_hash.hex()[:16]}..., "
            f"script={self.script_pubkey[:20].hex()}...)"
        )


# ---------------------------------------------------------------------------
# Transaction
# ---------------------------------------------------------------------------

class Transaction:
    """Tencoin transaction (SegWit-aware)."""

    def __init__(
        self,
        version: int = 1,
        vin: Optional[List[TxIn]] = None,
        vout: Optional[List[TxOut]] = None,   # may contain TimelockTxOut instances
        locktime: int = 0,
    ):
        self.version  = version
        self.vin      = vin  or []
        self.vout     = vout or []
        self.locktime = locktime

        self.has_witness = any(len(txin.witness) > 0 for txin in self.vin)

    def serialize(self, include_witness: bool = True) -> bytes:
        """
        Serialize transaction.

        Each output's serialize() method is called polymorphically, so
        TimelockTxOut instances automatically write the extended layout.
        """
        data  = struct.pack("<I", self.version)

        if self.has_witness and include_witness:
            data += b'\x00\x01'  # SegWit marker + flag

        data += encode_varint(len(self.vin))
        for txin in self.vin:
            data += txin.serialize()

        data += encode_varint(len(self.vout))
        for txout in self.vout:
            data += txout.serialize()   # polymorphic: handles both TxOut types

        if self.has_witness and include_witness:
            for txin in self.vin:
                data += encode_varint(len(txin.witness))
                for item in txin.witness:
                    data += encode_varint(len(item))
                    data += item

        data += struct.pack("<I", self.locktime)
        return data

    def txid(self) -> str:
        """Transaction ID (double-SHA256 of non-witness serialization)."""
        serialized  = self.serialize(include_witness=False)
        txid_bytes  = sha256d(serialized)[::-1]
        return txid_bytes.hex()

    def wtxid(self) -> str:
        """Witness transaction ID (includes witness data)."""
        serialized  = self.serialize(include_witness=True)
        wtxid_bytes = sha256d(serialized)[::-1]
        return wtxid_bytes.hex()

    def is_coinbase(self) -> bool:
        return len(self.vin) == 1 and self.vin[0].prev_txid == "0" * 64

    def calculate_size(self) -> int:
        return len(self.serialize(include_witness=True))

    def calculate_vsize(self) -> int:
        """Virtual size = weight / 4 (rounded up)."""
        if not self.has_witness:
            return self.calculate_size()

        base_size  = len(self.serialize(include_witness=False))
        total_size = len(self.serialize(include_witness=True))
        weight     = base_size * 3 + total_size
        return (weight + 3) // 4

    def __repr__(self) -> str:
        return (
            f"Transaction({self.txid()[:16]}..., "
            f"{len(self.vin)} in, {len(self.vout)} out)"
        )


# ---------------------------------------------------------------------------
# parse_transaction  — backward-compatible, detects TIMELOCK outputs
# ---------------------------------------------------------------------------

def parse_transaction(raw_hex: str) -> Transaction:
    """
    Parse a raw transaction hex string.

    Standard outputs and TIMELOCK conditional outputs (0xC1) are both
    handled.  The byte immediately following the 8-byte value field
    determines which path is taken:

        0xC1  → read time_mode (1 B) + lock_time (8 B), then script
        else  → treat that byte as the first byte of a varint script_len

    Returns:
        A Transaction whose vout list may contain TxOut or TimelockTxOut
        instances.
    """
    data   = bytes.fromhex(raw_hex)
    offset = 0

    # -- version --
    version = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    # -- SegWit marker --
    has_witness = False
    if offset + 2 <= len(data) and data[offset:offset + 2] == b'\x00\x01':
        has_witness = True
        offset += 2

    # -- inputs --
    vin_count, offset = decode_varint(data, offset)
    vin = []
    for _ in range(vin_count):
        prev_txid = data[offset:offset + 32][::-1].hex()
        offset   += 32

        vout_idx = struct.unpack_from("<I", data, offset)[0]
        offset  += 4

        script_len, offset = decode_varint(data, offset)
        script_sig = data[offset:offset + script_len]
        offset    += script_len

        sequence = struct.unpack_from("<I", data, offset)[0]
        offset  += 4

        vin.append(TxIn(prev_txid, vout_idx, script_sig, sequence))

    # -- outputs --
    vout_count, offset = decode_varint(data, offset)
    vout = []
    for _ in range(vout_count):
        value  = struct.unpack_from("<Q", data, offset)[0]
        offset += 8

        # Peek at the next byte to decide output type
        if offset < len(data) and data[offset] == COND_FLAG_TIMELOCK:
            # --- TIMELOCK conditional output ---
            offset   += 1                                          # consume 0xC1
            time_mode = struct.unpack_from("<B", data, offset)[0]
            offset   += 1
            lock_time = struct.unpack_from("<Q", data, offset)[0]
            offset   += 8

            script_len, offset = decode_varint(data, offset)
            script_pubkey = data[offset:offset + script_len]
            offset       += script_len

            vout.append(TimelockTxOut(value, script_pubkey, time_mode, lock_time))
        elif offset < len(data) and data[offset] == COND_FLAG_HASHLOCK:
            # --- HASHLOCK conditional output ---
            offset      += 1                                       # consume 0xC2
            secret_hash  = data[offset:offset + HASHLOCK_HASH_SIZE]
            offset      += HASHLOCK_HASH_SIZE

            script_len, offset = decode_varint(data, offset)
            script_pubkey = data[offset:offset + script_len]
            offset       += script_len

            vout.append(HashlockTxOut(value, script_pubkey, secret_hash))
        else:
            # --- standard output ---
            script_len, offset = decode_varint(data, offset)
            script_pubkey = data[offset:offset + script_len]
            offset       += script_len

            vout.append(TxOut(value, script_pubkey))

    # -- witness --
    if has_witness:
        for txin in vin:
            witness_count, offset = decode_varint(data, offset)
            witness = []
            for _ in range(witness_count):
                item_len, offset = decode_varint(data, offset)
                item    = data[offset:offset + item_len]
                offset += item_len
                witness.append(item)
            txin.witness = witness

    # -- locktime --
    locktime = struct.unpack_from("<I", data, offset)[0]

    return Transaction(version, vin, vout, locktime)
from typing import Any, Dict, List, Optional, Tuple

from ..constants import (
    DUST_LIMIT,
    OP_RETURN,
    OP_PUSHDATA1,
    OP_PUSHDATA2,
    OP_RETURN_MAX_DATA,
    OUTPUT_FLAG_RANGE,
    TMSG_MAGIC,
    TMSG_MIN_PAYMENT,
    COND_FLAG_TIMELOCK,
    TIMELOCK_MODE_HEIGHT,
    TIMELOCK_MODE_TIMESTAMP,
    HASHLOCK_MIN_PREIMAGE,
    HASHLOCK_MAX_PREIMAGE,
    HASHLOCK_HASH_SIZE,
)
from .core import Transaction, TxIn, TxOut, TimelockTxOut, HashlockTxOut
from .fee import FeeCalculator
from .address import address_to_script, is_valid_address


class TransactionBuilderError(Exception):
    """Raised when the transaction builder encounters an invalid state."""


class TransactionBuilder:
    """
    Build Tencoin transactions with support for all address types,
    including conditional TIMELOCK outputs.

    Features
    --------
    - P2WPKH, P2PKH, P2SH output addresses
    - TIMELOCK conditional outputs (flag 0xC1) via add_timelock_output()
    - HASHLOCK conditional outputs (flag 0xC2) via add_hashlock_output()
      (creation/locking side; spending a HASHLOCK UTXO lives in
      transaction/hashlock.py)
    - OP_RETURN metadata outputs via op_return()
    - Automatic fee calculation (rate-based or fixed)
    - Change address handling with dust-limit enforcement
    - SegWit and Legacy input modes

    Basic usage
    -----------
    >>> builder = TransactionBuilder()
    >>> builder.add_input(txid="...", vout=0, value=1_000_000,
    ...                   script_pubkey=b"...")
    >>> builder.add_output("tc1q...", 500_000)
    >>> builder.set_change_address("tc1q...")
    >>> tx, fee = builder.build()

    TIMELOCK usage
    --------------
    >>> # Lock 1 TEC until block #200,000
    >>> builder.add_timelock_output(
    ...     address="tc1q...",
    ...     amount=100_000_000,
    ...     lock_height=200_000,
    ... )

    >>> # Lock 0.5 TEC until 2028-01-01 00:00:00 UTC
    >>> builder.add_timelock_output(
    ...     address="tc1q...",
    ...     amount=50_000_000,
    ...     lock_timestamp=1_830_297_600,
    ... )

    HASHLOCK usage
    --------------
    >>> # Lock 1 TEC behind a secret (preimage) — recipient needs the
    >>> # preimage to spend it later.
    >>> builder.add_hashlock_output(
    ...     address="tc1q...",
    ...     amount=100_000_000,
    ...     preimage=b"my-secret-bytes",
    ... )

    >>> # Or supply a ready-made hash instead of a preimage:
    >>> builder.add_hashlock_output(
    ...     address="tc1q...",
    ...     amount=100_000_000,
    ...     secret_hash=bytes.fromhex("..."),
    ... )
    """

    def __init__(self) -> None:
        self.inputs:             List[Dict[str, Any]]   = []
        self.outputs:            List[Tuple[str, int]]  = []   # (address, amount)
        self.timelock_outputs:   List[TimelockTxOut]    = []   # pre-built TxOuts
        self.hashlock_outputs:   List[HashlockTxOut]    = []   # pre-built TxOuts
        self.op_return_outputs:  List[bytes]            = []   # raw payloads

        self.change_address: Optional[str] = None
        self.fee_rate:       int           = FeeCalculator.DEFAULT_FEE_RATE
        self._fixed_fee:     Optional[int] = None
        self.has_segwit:     bool          = True
        self.locktime:       int           = 0
        self.version:        int           = 1

    # ------------------------------------------------------------------
    # Input
    # ------------------------------------------------------------------

    def add_input(
        self,
        txid: str,
        vout: int,
        value: int,
        script_pubkey: bytes,
        sequence: int = 0xffffffff,
    ) -> "TransactionBuilder":
        """
        Add a UTXO as a transaction input.

        Args:
            txid:         Previous transaction ID (64-char hex, big-endian).
            vout:         Output index in the previous transaction.
            value:        UTXO amount in Tenos.
            script_pubkey: Locking script of the UTXO.
            sequence:     Sequence number (default 0xffffffff).

        Returns:
            self — for method chaining.
        """
        if not txid or len(txid) != 64:
            raise TransactionBuilderError(f"Invalid txid: {txid!r}")
        if vout < 0:
            raise TransactionBuilderError(f"Invalid vout: {vout}")
        if value <= 0:
            raise TransactionBuilderError(f"Invalid value: {value}")
        if not script_pubkey:
            raise TransactionBuilderError("script_pubkey cannot be empty")

        self.inputs.append({
            "txid":         txid,
            "vout":         vout,
            "value":        value,
            "script_pubkey": script_pubkey,
            "sequence":     sequence,
        })
        return self

    # ------------------------------------------------------------------
    # Standard output
    # ------------------------------------------------------------------

    def add_output(self, address: str, amount: int) -> "TransactionBuilder":
        """
        Add a standard (non-conditional) output.

        Args:
            address: Recipient address (P2WPKH, P2PKH, or P2SH).
            amount:  Amount in Tenos (must be >= DUST_LIMIT).

        Returns:
            self — for method chaining.
        """
        if amount < DUST_LIMIT:
            raise TransactionBuilderError(
                f"Amount {amount} is below dust limit {DUST_LIMIT}"
            )
        if not is_valid_address(address):
            raise TransactionBuilderError(f"Invalid address: {address!r}")

        self.outputs.append((address, amount))
        return self

    # ------------------------------------------------------------------
    # TIMELOCK output  (new)
    # ------------------------------------------------------------------

    def add_timelock_output(
        self,
        address: str,
        amount: int,
        lock_height: Optional[int] = None,
        lock_timestamp: Optional[int] = None,
    ) -> "TransactionBuilder":
        """
        Add a conditional TIMELOCK output (flag byte 0xC1).

        Exactly one of ``lock_height`` or ``lock_timestamp`` must be provided.

        On-chain layout written by TimelockTxOut.serialize():
            [value 8 B][0xC1][time_mode 1 B][lock_time 8 B]
            [varint script_len][script_pubkey]

        Args:
            address:        Recipient address (any valid type).
            amount:         Amount in Tenos (must be >= DUST_LIMIT).
            lock_height:    Lock until this block height is reached
                            (TIMELOCK_MODE_HEIGHT = 0x01).
            lock_timestamp: Lock until this Unix timestamp (seconds)
                            (TIMELOCK_MODE_TIMESTAMP = 0x02).

        Returns:
            self — for method chaining.

        Raises:
            TransactionBuilderError: On validation failure.

        Examples:
            >>> # Lock 1 TEC until block #200,000
            >>> builder.add_timelock_output(
            ...     address="tc1q...",
            ...     amount=100_000_000,
            ...     lock_height=200_000,
            ... )

            >>> # Lock 0.5 TEC until 2028-01-01 00:00:00 UTC
            >>> builder.add_timelock_output(
            ...     address="tc1q...",
            ...     amount=50_000_000,
            ...     lock_timestamp=1_830_297_600,
            ... )
        """
        # --- exactly one lock parameter ---
        if lock_height is None and lock_timestamp is None:
            raise TransactionBuilderError(
                "add_timelock_output() requires either lock_height or "
                "lock_timestamp — neither was supplied."
            )
        if lock_height is not None and lock_timestamp is not None:
            raise TransactionBuilderError(
                "add_timelock_output() accepts lock_height OR lock_timestamp, "
                "not both."
            )

        # --- resolve mode + value ---
        if lock_height is not None:
            time_mode = TIMELOCK_MODE_HEIGHT
            lock_time = lock_height
            if lock_time <= 0:
                raise TransactionBuilderError(
                    f"lock_height must be a positive integer, got {lock_time}"
                )
        else:
            time_mode = TIMELOCK_MODE_TIMESTAMP
            lock_time = lock_timestamp
            if lock_time <= 0:
                raise TransactionBuilderError(
                    f"lock_timestamp must be a positive Unix timestamp, "
                    f"got {lock_time}"
                )

        if lock_time >= 2 ** 64:
            raise TransactionBuilderError(
                f"lock_time exceeds uint64 range: {lock_time}"
            )

        # --- amount + address ---
        if amount < DUST_LIMIT:
            raise TransactionBuilderError(
                f"Amount {amount} is below dust limit {DUST_LIMIT}"
            )
        if not is_valid_address(address):
            raise TransactionBuilderError(f"Invalid address: {address!r}")

        script_pubkey = address_to_script(address)
        txout = TimelockTxOut(
            value=amount,
            script_pubkey=script_pubkey,
            time_mode=time_mode,
            lock_time=lock_time,
        )
        self.timelock_outputs.append(txout)
        return self

    # ------------------------------------------------------------------
    # HASHLOCK output  (new — creation/locking side only)
    # ------------------------------------------------------------------

    def add_hashlock_output(
        self,
        address: str,
        amount: int,
        preimage: Optional[bytes] = None,
        secret_hash: Optional[bytes] = None,
    ) -> "TransactionBuilder":
        """
        Add a conditional HASHLOCK output (flag byte 0xC2).

        This builds the LOCKING side of a HASHLOCK output only: it locks
        funds behind a secret so that whoever later reveals the matching
        preimage can spend them. The spending side (providing a preimage
        to unlock an existing HASHLOCK UTXO) is in transaction/hashlock.py.

        Exactly one of ``preimage`` or ``secret_hash`` must be provided:
          - Pass ``preimage`` to have the builder hash it for you
            (secret_hash = SHA256(preimage), single round — not double).
          - Pass ``secret_hash`` directly if you already have the 32-byte
            hash and don't want to (or can't) share the preimage with the
            builder.

        On-chain layout written by HashlockTxOut.serialize():
            [value 8 B][0xC2][secret_hash 32 B]
            [varint script_len][script_pubkey]

        Args:
            address:     Recipient address (any valid type).
            amount:      Amount in Tenos (must be >= DUST_LIMIT).
            preimage:    Raw secret bytes, 1..64 bytes. Text must be
                         UTF-8-encoded by the caller before passing it in.
                         Case and exact bytes matter — nothing here
                         normalises or re-encodes the preimage.
            secret_hash: Precomputed SHA256(preimage), exactly 32 bytes.

        Returns:
            self — for method chaining.

        Raises:
            TransactionBuilderError: On validation failure.

        Examples:
            >>> # Lock 1 TEC behind a secret
            >>> builder.add_hashlock_output(
            ...     address="tc1q...",
            ...     amount=100_000_000,
            ...     preimage=b"correct horse battery staple",
            ... )

            >>> # Lock funds using a hash you already computed elsewhere
            >>> builder.add_hashlock_output(
            ...     address="tc1q...",
            ...     amount=100_000_000,
            ...     secret_hash=bytes.fromhex("9f86d0..."),
            ... )
        """
        # --- exactly one of preimage / secret_hash ---
        if preimage is None and secret_hash is None:
            raise TransactionBuilderError(
                "add_hashlock_output() requires either preimage or "
                "secret_hash — neither was supplied."
            )
        if preimage is not None and secret_hash is not None:
            raise TransactionBuilderError(
                "add_hashlock_output() accepts preimage OR secret_hash, "
                "not both."
            )

        if preimage is not None:
            if not isinstance(preimage, (bytes, bytearray)):
                raise TransactionBuilderError(
                    f"preimage must be bytes, got {type(preimage).__name__} "
                    "(encode text as UTF-8 before passing it in)"
                )
            if len(preimage) < HASHLOCK_MIN_PREIMAGE:
                raise TransactionBuilderError(
                    f"preimage too short: {len(preimage)} byte(s), "
                    f"minimum is {HASHLOCK_MIN_PREIMAGE}"
                )
            if len(preimage) > HASHLOCK_MAX_PREIMAGE:
                raise TransactionBuilderError(
                    f"preimage too long: {len(preimage)} bytes, "
                    f"maximum is {HASHLOCK_MAX_PREIMAGE}"
                )
            import hashlib
            resolved_hash = hashlib.sha256(bytes(preimage)).digest()
        else:
            if not isinstance(secret_hash, (bytes, bytearray)) or len(secret_hash) != HASHLOCK_HASH_SIZE:
                raise TransactionBuilderError(
                    f"secret_hash must be exactly {HASHLOCK_HASH_SIZE} bytes, "
                    f"got {len(secret_hash) if isinstance(secret_hash, (bytes, bytearray)) else type(secret_hash).__name__}"
                )
            resolved_hash = bytes(secret_hash)

        # --- amount + address ---
        if amount < DUST_LIMIT:
            raise TransactionBuilderError(
                f"Amount {amount} is below dust limit {DUST_LIMIT}"
            )
        if not is_valid_address(address):
            raise TransactionBuilderError(f"Invalid address: {address!r}")

        script_pubkey = address_to_script(address)
        txout = HashlockTxOut(
            value=amount,
            script_pubkey=script_pubkey,
            secret_hash=resolved_hash,
        )
        self.hashlock_outputs.append(txout)
        return self

    # ------------------------------------------------------------------
    # OP_RETURN output
    # ------------------------------------------------------------------

    def op_return(self, data) -> "TransactionBuilder":
        """
        Add an OP_RETURN metadata output (value = 0, unspendable).

        Args:
            data: Payload as ``str`` (UTF-8 encoded) or ``bytes``.
                  Maximum OP_RETURN_MAX_DATA (1024) bytes after encoding.
                  A payload whose script would be 193..207 bytes long (payload of
                  190..204 bytes) is refused: that length is indistinguishable from a
                  conditional-output flag byte when the output is parsed.

        Returns:
            self — for method chaining.
        """
        if isinstance(data, str):
            payload = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray)):
            payload = bytes(data)
        else:
            raise TransactionBuilderError(
                f"op_return data must be str or bytes, got {type(data).__name__}"
            )
        if len(payload) > OP_RETURN_MAX_DATA:
            raise TransactionBuilderError(
                f"OP_RETURN payload too large: {len(payload)} bytes (max {OP_RETURN_MAX_DATA})"
            )
        script_len = len(self._build_op_return_script(payload))
        if script_len in OUTPUT_FLAG_RANGE:
            raise TransactionBuilderError(
                f"OP_RETURN payload of {len(payload)} bytes makes a {script_len}-byte script, "
                f"which collides with the conditional-output flag bytes "
                f"0x{OUTPUT_FLAG_RANGE.start:02x}..0x{OUTPUT_FLAG_RANGE[-1]:02x}; "
                "make the payload shorter or longer"
            )
        self.op_return_outputs.append(payload)
        return self

    # ------------------------------------------------------------------
    # TMSG output pair: payment + OP_RETURN
    # ------------------------------------------------------------------

    def add_tmsg_output(
        self,
        address: str,
        payload: bytes,
        amount: int = TMSG_MIN_PAYMENT,
    ) -> "TransactionBuilder":
        """
        Add the first two outputs of an on-chain TMSG transaction:

            output 0  ``amount`` Tenos to ``address`` (the recipient)
            output 1  OP_RETURN carrying the encrypted TMSG payload

        The dust limit does NOT apply here: transactions that carry a TMSG may pay as
        little as TMSG_MIN_PAYMENT (1 Teno). Call it on a builder with no outputs yet;
        the change output (if any) is appended by ``build()`` as output 2.

        Args:
            address: Recipient address.
            payload: Complete TMSG payload (starts with ``b"TMSG"``), e.g. ``tmsg.encrypt(...)``.
            amount:  Tenos paid to the recipient (default 1, may be increased).
        """
        if self.outputs or self.timelock_outputs or self.hashlock_outputs or self.op_return_outputs:
            raise TransactionBuilderError(
                "add_tmsg_output() must be called on a builder without outputs "
                "(the recipient must be output 0 and the OP_RETURN output 1)"
            )
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < TMSG_MIN_PAYMENT:
            raise TransactionBuilderError(
                f"TMSG payment must be an integer >= {TMSG_MIN_PAYMENT} Teno, got {amount!r}"
            )
        if not is_valid_address(address):
            raise TransactionBuilderError(f"Invalid address: {address!r}")
        if not isinstance(payload, (bytes, bytearray)) or not bytes(payload).startswith(TMSG_MAGIC):
            raise TransactionBuilderError("payload is not a TMSG (it must start with b'TMSG')")

        self.op_return(bytes(payload))          # size + script-length checks
        self.outputs.append((address, amount))  # dust exemption: bypasses add_output()
        return self

    # ------------------------------------------------------------------
    # Change address
    # ------------------------------------------------------------------

    def set_change_address(self, address: str) -> "TransactionBuilder":
        """Set the change address."""
        if not is_valid_address(address):
            raise TransactionBuilderError(
                f"Invalid change address: {address!r}"
            )
        self.change_address = address
        return self

    # ------------------------------------------------------------------
    # Fee controls
    # ------------------------------------------------------------------

    def set_fee_rate(self, fee_rate: int) -> "TransactionBuilder":
        """Set fee rate in Tenos per byte (clears any fixed fee)."""
        if fee_rate < 0:
            raise TransactionBuilderError(f"Invalid fee rate: {fee_rate}")
        self.fee_rate    = fee_rate
        self._fixed_fee  = None
        return self

    def set_fee(self, amount, unit: str = "Teno") -> "TransactionBuilder":
        """
        Set an exact fixed fee (overrides set_fee_rate).

        Args:
            amount: Fee amount.
            unit:   "TEC" or "Teno" (case-insensitive).

        Examples:
            >>> builder.set_fee(0.0022, unit="TEC")   # → 220_000 Teno
            >>> builder.set_fee(220_000)               # → 220_000 Teno
        """
        from ..constants import TENOS_PER_TEC

        unit_norm = unit.strip().lower()
        if unit_norm == "tec":
            fee_teno = round(float(amount) * TENOS_PER_TEC)
        elif unit_norm in ("teno", "tenos"):
            fee_teno = int(amount)
            if fee_teno != float(amount):
                raise TransactionBuilderError(
                    f"Teno amount must be a whole number, got {amount}"
                )
        else:
            raise TransactionBuilderError(
                f"Unknown fee unit '{unit}'. Use 'TEC' or 'Teno'."
            )
        if fee_teno < 0:
            raise TransactionBuilderError(f"Fee cannot be negative: {fee_teno}")

        self._fixed_fee = fee_teno
        return self

    # ------------------------------------------------------------------
    # Misc controls
    # ------------------------------------------------------------------

    def set_segwit(self, use_segwit: bool) -> "TransactionBuilder":
        """Toggle SegWit input mode."""
        self.has_segwit = use_segwit
        return self

    def set_locktime(self, locktime: int) -> "TransactionBuilder":
        """Set transaction nLockTime."""
        if locktime < 0:
            raise TransactionBuilderError(f"Invalid locktime: {locktime}")
        self.locktime = locktime
        return self

    def set_version(self, version: int) -> "TransactionBuilder":
        """Set transaction version."""
        if version < 1:
            raise TransactionBuilderError(f"Invalid version: {version}")
        self.version = version
        return self

    # ------------------------------------------------------------------
    # Calculation helpers
    # ------------------------------------------------------------------

    def calculate_total_input(self) -> int:
        """Total value of all inputs in Tenos."""
        return sum(inp["value"] for inp in self.inputs)

    def calculate_total_output(self) -> int:
        """
        Total value of all non-change outputs (standard + timelock + hashlock).
        OP_RETURN outputs carry zero value and are not included.
        """
        standard  = sum(amount for _, amount in self.outputs)
        timelocks = sum(txout.value for txout in self.timelock_outputs)
        hashlocks = sum(txout.value for txout in self.hashlock_outputs)
        return standard + timelocks + hashlocks

    def calculate_fee(self, include_change: bool = True) -> int:
        """Estimated fee based on current fee_rate."""
        num_inputs  = len(self.inputs)
        num_outputs = (
            len(self.outputs)
            + len(self.timelock_outputs)
            + len(self.hashlock_outputs)
            + len(self.op_return_outputs)
        )
        if include_change and self.change_address:
            num_outputs += 1

        return FeeCalculator.calculate_fee(
            num_inputs, num_outputs, self.fee_rate, self.has_segwit
        )

    def calculate_change(self) -> Tuple[int, bool]:
        """
        Calculate change amount.

        Returns:
            (change_amount, has_change)
        """
        total_input  = self.calculate_total_input()
        total_output = self.calculate_total_output()
        fee          = self.calculate_fee(include_change=False)
        remaining    = total_input - total_output - fee

        if remaining < 0:
            raise TransactionBuilderError(
                f"Insufficient funds: have {total_input}, "
                f"need {total_output + fee}"
            )
        if remaining >= DUST_LIMIT and self.change_address:
            return remaining, True
        return 0, False

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build_op_return_script(self, payload: bytes) -> bytes:
        """Encode an OP_RETURN locking script for the given payload."""
        script = bytes([OP_RETURN])
        if not payload:
            return script
        if len(payload) <= 0x4B:
            script += bytes([len(payload)]) + payload
        elif len(payload) <= 0xFF:
            script += bytes([OP_PUSHDATA1, len(payload)]) + payload
        else:
            script += bytes([OP_PUSHDATA2]) + len(payload).to_bytes(2, "little") + payload
        return script

    def build(self) -> Tuple[Transaction, int]:
        """
        Build and return the transaction together with the actual fee.

        Returns:
            (Transaction, fee_in_tenos)

        Raises:
            TransactionBuilderError: If the transaction cannot be built.
        """
        # --- validation ---
        if not self.inputs:
            raise TransactionBuilderError("No inputs added")
        if (not self.outputs and not self.timelock_outputs
                and not self.hashlock_outputs and not self.op_return_outputs):
            raise TransactionBuilderError("No outputs added")

        total_input  = self.calculate_total_input()
        total_output = self.calculate_total_output()

        # --- build TxIn list ---
        tx_inputs = [
            TxIn(
                prev_txid=inp["txid"],
                vout=inp["vout"],
                script_sig=b"",
                sequence=inp["sequence"],
            )
            for inp in self.inputs
        ]

        # --- build standard TxOut list ---
        tx_outputs: List[TxOut] = [
            TxOut(amount, address_to_script(address))
            for address, amount in self.outputs
        ]

        # --- append pre-built TimelockTxOut objects ---
        tx_outputs.extend(self.timelock_outputs)

        # --- append pre-built HashlockTxOut objects ---
        tx_outputs.extend(self.hashlock_outputs)

        # --- append OP_RETURN outputs ---
        for payload in self.op_return_outputs:
            tx_outputs.append(TxOut(0, self._build_op_return_script(payload)))

        # ── fee resolution ──────────────────────────────────────────────
        if self._fixed_fee is not None:
            fee       = self._fixed_fee
            remaining = total_input - total_output - fee

            has_change    = False
            change_amount = 0

            if remaining < 0:
                raise TransactionBuilderError(
                    f"Insufficient funds: have {total_input}, "
                    f"need {total_output + fee}"
                )
            if remaining >= DUST_LIMIT and self.change_address:
                has_change    = True
                change_amount = remaining
            # 0 <= remaining < DUST_LIMIT → goes to miner as extra fee

        else:
            # ── rate-based fee ──────────────────────────────────────────
            witness_size_per_input = 108

            temp_tx = Transaction(
                version=self.version,
                vin=tx_inputs,
                vout=tx_outputs,
                locktime=self.locktime,
            )

            if self.has_segwit:
                base_size    = len(temp_tx.serialize(include_witness=False))
                total_w_size = len(tx_inputs) * witness_size_per_input
                total_size   = base_size + total_w_size
                weight       = base_size * 3 + total_size
                temp_size    = (weight + 3) // 4
            else:
                temp_size = temp_tx.calculate_size()

            min_fee             = 1000
            fee_without_change  = max(temp_size * self.fee_rate, min_fee)
            remaining           = total_input - total_output - fee_without_change

            has_change    = False
            change_amount = 0

            if remaining >= DUST_LIMIT and self.change_address:
                change_script  = address_to_script(self.change_address)
                change_output  = TxOut(remaining, change_script)

                tx_with_change = Transaction(
                    version=self.version,
                    vin=tx_inputs,
                    vout=tx_outputs + [change_output],
                    locktime=self.locktime,
                )

                if self.has_segwit:
                    base_size    = len(tx_with_change.serialize(include_witness=False))
                    total_w_size = len(tx_inputs) * witness_size_per_input
                    total_size   = base_size + total_w_size
                    weight       = base_size * 3 + total_size
                    size_with_change = (weight + 3) // 4
                else:
                    size_with_change = tx_with_change.calculate_size()

                fee_with_change = max(size_with_change * self.fee_rate, min_fee)
                change_amount   = total_input - total_output - fee_with_change

                if change_amount >= DUST_LIMIT:
                    has_change = True
                    fee        = fee_with_change
                else:
                    fee = fee_without_change + remaining
            else:
                fee = fee_without_change

        # --- final verification ---
        required = total_output + fee + (change_amount if has_change else 0)
        if total_input < required:
            raise TransactionBuilderError(
                f"Insufficient funds: have {total_input}, need {required}"
            )

        # --- append change output ---
        if has_change and self.change_address:
            change_script = address_to_script(self.change_address)
            tx_outputs.append(TxOut(change_amount, change_script))

        tx = Transaction(
            version=self.version,
            vin=tx_inputs,
            vout=tx_outputs,
            locktime=self.locktime,
        )

        actual_total_output = sum(out.value for out in tx.vout)
        actual_fee          = total_input - actual_total_output
        return tx, actual_fee

    def build_raw(self) -> Tuple[str, int]:
        """Build and return (raw_hex, fee)."""
        tx, fee = self.build()
        return tx.serialize().hex(), fee

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_summary(self) -> Dict[str, Any]:
        """Return a dict describing the current builder state."""
        total_input  = self.calculate_total_input()
        total_output = self.calculate_total_output()

        try:
            change_amount, has_change = self.calculate_change()
            fee = self.calculate_fee(include_change=has_change)
        except TransactionBuilderError:
            change_amount = 0
            has_change    = False
            fee           = self.calculate_fee(include_change=False)

        timelock_summary = [
            {
                "value":           txout.value,
                "time_mode":       txout.lock_mode_name(),
                "lock_time":       txout.lock_time,        # raw uint64 (protocol)
                "lock_time_human": txout.lock_time_human,  # display only
            }
            for txout in self.timelock_outputs
        ]

        hashlock_summary = [
            {
                "value":       txout.value,
                "secret_hash": txout.secret_hash.hex(),
            }
            for txout in self.hashlock_outputs
        ]

        return {
            "inputs_count":          len(self.inputs),
            "outputs_count":         (
                len(self.outputs)
                + len(self.timelock_outputs)
                + len(self.hashlock_outputs)
                + len(self.op_return_outputs)
                + (1 if has_change else 0)
            ),
            "standard_outputs_count":  len(self.outputs),
            "timelock_outputs_count":  len(self.timelock_outputs),
            "hashlock_outputs_count":  len(self.hashlock_outputs),
            "op_return_count":         len(self.op_return_outputs),
            "total_input":             total_input,
            "total_output":            total_output,
            "change_amount":           change_amount,
            "has_change":              has_change,
            "fee":                     fee,
            "fee_rate":                self.fee_rate,
            "fixed_fee":               self._fixed_fee,
            "uses_segwit":             self.has_segwit,
            "locktime":                self.locktime,
            "version":                 self.version,
            "change_address":          self.change_address if has_change else None,
            "timelock_outputs":        timelock_summary,
            "hashlock_outputs":        hashlock_summary,
        }

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def clear(self) -> "TransactionBuilder":
        """Reset builder to initial state."""
        self.inputs.clear()
        self.outputs.clear()
        self.timelock_outputs.clear()
        self.hashlock_outputs.clear()
        self.op_return_outputs.clear()
        self.change_address = None
        self.fee_rate       = FeeCalculator.DEFAULT_FEE_RATE
        self._fixed_fee     = None
        self.has_segwit     = True
        self.locktime       = 0
        self.version        = 1
        return self

    def copy(self) -> "TransactionBuilder":
        """Return a deep copy of this builder."""
        import copy
        nb = TransactionBuilder()
        nb.inputs            = copy.deepcopy(self.inputs)
        nb.outputs           = self.outputs.copy()
        nb.timelock_outputs  = self.timelock_outputs.copy()   # TimelockTxOut is immutable after construction
        nb.hashlock_outputs  = self.hashlock_outputs.copy()    # HashlockTxOut is immutable after construction
        nb.op_return_outputs = self.op_return_outputs.copy()
        nb.change_address    = self.change_address
        nb.fee_rate          = self.fee_rate
        nb._fixed_fee        = self._fixed_fee
        nb.has_segwit        = self.has_segwit
        nb.locktime          = self.locktime
        nb.version           = self.version
        return nb

    def __repr__(self) -> str:
        s = self.get_summary()
        return (
            f"TransactionBuilder("
            f"inputs={s['inputs_count']}, "
            f"outputs={s['outputs_count']}, "
            f"timelock={s['timelock_outputs_count']}, "
            f"hashlock={s['hashlock_outputs_count']}, "
            f"total={s['total_input']} Tenos)"
        )
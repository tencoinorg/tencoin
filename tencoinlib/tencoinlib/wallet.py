# tencoinlib/wallet.py
"""
Main Wallet class — HD wallet with locked/unlocked state machine.

Security model
--------------
A Wallet object can be in one of two states:

  LOCKED
    - No secret material (seed, mnemonic, xprv, private keys) is held in RAM.
    - Public metadata (address, xpub, derivation path, indices) is available.
    - The .tcw file on disk is always encrypted.

  UNLOCKED
    - Secret material is present in volatile attributes (_seed, _mnemonic,
      _master_xprv, _imported_xprv).
    - All wallet operations are available.
    - Call lock() or use the context manager to discard secrets from RAM.

Lifecycle:
    wallet = Wallet.create(password)         # new wallet → LOCKED
    wallet = Wallet.recover(mnemonic, pw)    # from mnemonic → LOCKED
    wallet = Wallet.load("wallet.tcw")       # load header only → LOCKED

    wallet.save("wallet.tcw", password)      # encrypt → disk
    wallet.unlock(password)                  # decrypt → UNLOCKED
    wallet.sign_transaction(...)             # requires UNLOCKED
    wallet.lock()                            # zeroize → LOCKED

    # Context-manager form (auto-lock):
    with wallet.unlocked(password):
        tx = wallet.sign_transaction(...)

File format
-----------
Files use the TCW v1 binary format (see wallet_storage/tcw.py):
    AES-256-GCM encryption, Argon2id KDF, binary header with AAD.

Address types
-------------
The wallet's *canonical* address type is determined at construction:
  - create() / recover()  → P2PKH (BIP-44, m/44'/COIN_TYPE'/0'/0/0)
  - from_xpub()           → P2WPKH (derived from provided xpub at 0/0)
  - from_xprv()           → P2PKH  (derived from provided xprv at 0/0)
  - from_private_key()    → P2PKH  (raw key, no chain code, no HD tree)

get_address(type=...) allows on-the-fly derivation of other address
forms (P2WPKH native SegWit via BIP-84, P2SH nested SegWit via BIP-49,
P2WSH) from the seed.  These are not the canonical wallet identity and
are not stored in the .tcw file.  Not available on from_private_key()
wallets, which have no chain code to derive anything else from.

Each address type is derived under its own BIP-32 purpose field, with
no path shared between them:
  P2PKH        -> BIP-44 -> m/44'/COIN_TYPE'/account'/change/index
  P2SH-P2WPKH  -> BIP-49 -> m/49'/COIN_TYPE'/account'/change/index
  P2WPKH       -> BIP-84 -> m/84'/COIN_TYPE'/account'/change/index

ESP32 bridge
------------
export_to_esp_blob()/import_from_esp_blob() and the module-level
wallet_storage.esp_bridge helpers (esp_blob_to_tcw_file /
tcw_file_to_esp_blob) translate wallet secrets to/from the ESP32
firmware's own encrypted blob format (TCE1: PBKDF2-HMAC-SHA256 instead
of Argon2id, since ESP32 cannot run Argon2id). Only "hd" and "privkey"
wallets have an ESP equivalent; see wallet_storage/esp_bridge.py.
"""

import json
import os
from contextlib import contextmanager
from typing import Dict, Generator, List, Optional, Tuple, Union

from .keys.bip32 import (
    ExtendedPrivateKey,
    ExtendedPublicKey,
    HARDENED_OFFSET,
    path_to_indices,
    derive_path_from_seed,
)
from .keys.bip39 import (
    generate_mnemonic,
    mnemonic_to_seed,
    validate_mnemonic,
)
from .keys.bip84 import get_default_address_from_seed, public_key_to_segwit_v0
from .keys.bip44 import bip44_account_path
from .keys.bip49 import bip49_account_path, public_key_to_p2sh_segwit
from .constants import BIP44_PURPOSE, BIP49_PURPOSE, BIP84_PURPOSE, COIN_TYPE, DERIVATION_PATH
from .transaction.script import (
    build_multisig_script,
    pubkey_to_p2pkh_address,
    pubkey_to_p2sh_p2pkh_address,
    script_to_p2sh_address,
    script_to_p2wsh_address,
)
from .wallet_storage import save_wallet, load_wallet, read_header, TCWHeader
from .wallet_storage.tcw import TCWFormatError, TCWAuthError, TCWVersionError
from .wallet_storage.kdf import verify_password_strength


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class WalletError(Exception):
    """General wallet error."""


class WalletLockedError(WalletError):
    """Raised when a secret-requiring operation is attempted on a locked wallet."""


class WalletAuthError(WalletError):
    """Raised when unlock() is called with the wrong password."""


# ---------------------------------------------------------------------------
# Wallet class
# ---------------------------------------------------------------------------

class Wallet:
    """
    HD Wallet for Tencoin (BIP-39 + BIP-44 + full BIP-32).

    Supports:
      - Seed-based wallets (create / recover)
      - xpub-only watch-only wallets (from_xpub)
      - xprv-only wallets without mnemonic (from_xprv)
      - Locked / unlocked state machine with TCW v1 encrypted storage
    """

    # ------------------------------------------------------------------
    # Construction helpers  (internal — do not call directly)
    # ------------------------------------------------------------------

    def __new__(cls) -> "Wallet":
        """Allocate a blank Wallet; all attributes set by class-methods."""
        instance = super().__new__(cls)
        # Public / non-secret metadata
        instance.address:          str  = ""
        instance.public_key:       str  = ""
        instance.derivation_path:  str  = ""
        instance.account_index:    int  = 0
        instance.change_index:     int  = 0
        instance.address_index:    int  = 0
        instance.is_watch_only:    bool = False
        instance._wallet_type:     str  = "hd"  # "hd" | "xpub" | "xprv"

        # Public extended keys (not secret; available while locked)
        instance._master_xpub:    Optional[ExtendedPublicKey] = None
        instance._imported_xpub:  Optional[str]               = None

        # Volatile / secret attributes — None when locked
        instance._seed:           Optional[bytes]              = None
        instance._mnemonic:       Optional[str]                = None
        instance._master_xprv:    Optional[ExtendedPrivateKey] = None
        instance._private_key:    Optional[bytes]              = None
        instance._imported_xprv:  Optional[str]               = None

        instance._locked:         bool = True
        return instance

    # ------------------------------------------------------------------
    # Public constructors
    # ------------------------------------------------------------------

    @classmethod
    def create(cls, strength: int = 128) -> "Wallet":
        """
        Create a new HD wallet (BIP-39 mnemonic + BIP-32/BIP-44).

        The returned wallet is UNLOCKED (secrets are in RAM).
        Call save() to persist to a TCW file, then lock() or use the
        context manager.

        Args:
            strength: Entropy strength in bits (128 → 12 words).

        Returns:
            UNLOCKED Wallet instance.
        """
        mnemonic = generate_mnemonic(strength)
        seed     = mnemonic_to_seed(mnemonic)
        return cls._from_seed(seed, mnemonic)

    @classmethod
    def recover(cls, mnemonic: str, passphrase: str = "") -> "Wallet":
        """
        Recover wallet from mnemonic phrase.

        The returned wallet is UNLOCKED.

        Args:
            mnemonic:   12/15/18/21/24-word BIP-39 phrase.
            passphrase: Optional BIP-39 passphrase.

        Returns:
            UNLOCKED Wallet instance.
        """
        if not validate_mnemonic(mnemonic):
            raise WalletError("Invalid mnemonic phrase")
        seed = mnemonic_to_seed(mnemonic, passphrase)
        return cls._from_seed(seed, mnemonic)

    @classmethod
    def from_xpub(cls, xpub: str) -> "Wallet":
        """
        Create a watch-only wallet from an account/master xpub.

        The base xpub is treated as the root; addresses are derived as
        change/index (e.g. 0/0, 0/1, 1/0, …).

        The returned wallet is UNLOCKED (xpub is not secret).
        Watch-only wallets cannot sign transactions.
        """
        ext_pub   = ExtendedPublicKey.from_xpub(xpub)
        child_pub = ext_pub.derive_path("0/0").key
        address   = public_key_to_segwit_v0(child_pub)

        w = cls()
        w.address         = address
        w.public_key      = child_pub.hex()
        w.is_watch_only   = True
        w._wallet_type    = "xpub"
        w._master_xpub    = ext_pub
        w._imported_xpub  = xpub
        w._locked         = False   # xpub is not secret
        return w

    @classmethod
    def from_xprv(cls, xprv: str) -> "Wallet":
        """
        Create a wallet from a master/account xprv.

        No mnemonic or seed required.  The returned wallet is UNLOCKED.
        """
        ext_priv  = ExtendedPrivateKey.from_xprv(xprv)
        ext_pub   = ext_priv.to_public()
        child_priv = ext_priv.derive_path("0/0")
        child_pub  = child_priv.to_public().key
        address    = public_key_to_segwit_v0(child_pub)

        w = cls()
        w.address         = address
        w.public_key      = child_pub.hex()
        w.is_watch_only   = False
        w._wallet_type    = "xprv"
        w._master_xprv    = ext_priv
        w._master_xpub    = ext_pub
        w._private_key    = child_priv.key
        w._imported_xprv  = xprv
        w._imported_xpub  = ext_pub.to_xpub()
        w._locked         = False
        return w

    @classmethod
    def from_private_key(cls, private_key: Union[bytes, str]) -> "Wallet":
        """
        Create a wallet from a single raw 32-byte private key — no
        mnemonic, no seed, no BIP-32 chain code, no HD derivation.

        This is distinct from from_xprv(): an xprv carries a chain code
        and can derive a whole tree of child keys, while a bare private
        key cannot derive anything else. It exists to round-trip the
        ESP32 firmware's "imported" wallet type (see
        wallet_storage/esp_bridge.py), which stores exactly this: one
        key, nothing more.

        The returned wallet is UNLOCKED. Its canonical address is
        legacy P2PKH, matching the ESP firmware. Operations that need a
        chain code (get_master_xprv/xpub, derive_xprv/xpub,
        get_account_xprv/xpub, get_address("p2wpkh"/"p2sh")) are not
        available on this wallet type and raise WalletError.

        Args:
            private_key: 32 bytes, a 64-char hex string, or a WIF string. The form is
                         detected automatically. A WIF of an UNCOMPRESSED key is refused:
                         this wallet only uses compressed keys, so it would not have the
                         address that key's funds are at (spend those with the signer
                         classes instead, see keys.wif.decode_wif).

        Returns:
            UNLOCKED Wallet instance (wallet_type == "privkey").
        """
        from .keys.ec import privkey_to_pubkey
        from .keys.wif import WIFError, parse_private_key

        try:
            info = parse_private_key(private_key)
        except WIFError as exc:
            raise WalletError(f"Invalid private key: {exc}") from exc
        if info.compressed is False:
            raise WalletError(
                "This WIF is for an UNCOMPRESSED key, but wallets only use compressed keys: "
                "the wallet address would differ from the address that WIF controls. "
                "Use keys.wif.decode_wif() and the signer classes for uncompressed keys."
            )
        key_bytes = info.private_key

        pub  = privkey_to_pubkey(key_bytes, compressed=True)
        addr = pubkey_to_p2pkh_address(pub)

        w = cls()
        w.address        = addr
        w.public_key     = pub.hex()
        w.is_watch_only  = False
        w._wallet_type   = "privkey"
        w._private_key   = key_bytes
        w._locked        = False
        return w

    @classmethod
    def _resolve_filepath(cls, filepath: str) -> str:
        """
        Resolve the actual path of a TCW file.

        Rules:
        - If the caller supplied a ``.tcw`` extension (case-insensitive),
          use the path as-is (and raise FileNotFoundError if not found).
        - If NO extension was given, first try ``filepath`` as-is; if that
          does not exist, append ``.tcw`` and try again.

        Examples:
            "my_wallet"          → tries my_wallet, then my_wallet.tcw
            "my_wallet.tcw"      → uses my_wallet.tcw  (exact)
            "backup.TCW"         → uses backup.TCW      (exact)
        """
        has_extension = filepath.lower().endswith(".tcw")

        if has_extension:
            # Caller was explicit — honour it exactly.
            return filepath

        # No extension: try the bare name first, then with .tcw appended.
        if os.path.exists(filepath):
            return filepath

        with_ext = filepath + ".tcw"
        if os.path.exists(with_ext):
            return with_ext

        # Neither exists — raise a helpful error pointing to the .tcw variant.
        raise FileNotFoundError(
            f"Wallet file not found: '{filepath}' or '{with_ext}'"
        )

    @classmethod
    def load(cls, filepath: str) -> "Wallet":
        """
        Load a TCW wallet file WITHOUT decrypting it.

        The returned wallet is LOCKED.  Call unlock(password) before
        using any operation that requires secret material.

        The ``.tcw`` extension is resolved automatically if omitted:
            Wallet.load("my_wallet")      # finds my_wallet.tcw automatically
            Wallet.load("my_wallet.tcw")  # explicit path, used as-is
            Wallet.load("backup.TCW")     # explicit path, used as-is

        To go directly to an unlocked wallet:
            wallet = Wallet.load(path).unlock(password)
            # or
            with Wallet.load(path).unlocked(password) as wallet:
                ...

        Args:
            filepath:  Path to a .tcw file (extension optional).

        Returns:
            LOCKED Wallet instance.

        Raises:
            TCWFormatError:    File is not a valid TCW container.
            TCWVersionError:   File version is not supported.
            FileNotFoundError: File does not exist.
        """
        filepath = cls._resolve_filepath(filepath)

        # Validate that it's a real TCW file by reading the header.
        _header: TCWHeader = read_header(filepath)   # raises on bad magic/version

        w = cls()
        w._tcw_filepath = filepath
        w._locked       = True
        return w

    # ------------------------------------------------------------------
    # Lock / unlock
    # ------------------------------------------------------------------

    def unlock(self, password: str) -> "Wallet":
        """
        Decrypt the wallet's TCW file and load secrets into RAM.

        Sets the wallet state to UNLOCKED.  Returns self for chaining:
            wallet.unlock(password).sign_transaction(tx)

        Args:
            password:  The passphrase used when the wallet was saved.

        Returns:
            self (UNLOCKED)

        Raises:
            WalletAuthError:  Wrong password or corrupted file.
            WalletError:      If the wallet was not created via load()
                              (has no associated TCW file).
            TCWFormatError:   If the file is structurally invalid.
        """
        if not self._locked:
            return self   # already unlocked

        filepath = getattr(self, "_tcw_filepath", None)
        if not filepath:
            raise WalletError(
                "unlock() requires a wallet loaded from a .tcw file. "
                "Use Wallet.load(filepath) first."
            )

        try:
            payload = load_wallet(filepath, password)
        except TCWAuthError as exc:
            raise WalletAuthError(str(exc)) from exc

        self._load_from_payload(payload)
        self._locked = False
        return self

    def lock(self) -> None:
        """
        Discard all secret material from RAM and set state to LOCKED.

        Best-effort zeroization is performed where Python allows it.
        Public metadata (address, xpub, indices) is preserved.
        """
        # Zeroize bytearray secrets where possible
        _zeroize_attr(self, "_seed")
        _zeroize_attr(self, "_private_key")

        # Drop all secret references
        self._seed          = None
        self._mnemonic      = None
        self._master_xprv   = None
        self._private_key   = None
        self._imported_xprv = None

        self._locked = True

    @contextmanager
    def unlocked(self, password: str) -> Generator["Wallet", None, None]:
        """
        Context manager: unlock, yield self, then lock automatically.

        Usage:
            with wallet.unlocked("my-password") as w:
                signed_tx = w.sign_transaction(tx)
        """
        self.unlock(password)
        try:
            yield self
        finally:
            self.lock()

    @property
    def is_locked(self) -> bool:
        """True when no secret material is held in RAM."""
        return self._locked

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_filepath(filepath: str) -> str:
        """
        Ensure filepath ends with .tcw (case-insensitive), then find a
        non-colliding filename by appending ``_N`` before the extension
        if the resolved path already exists on disk.

        The suffix uses the preserved original extension casing so that
        ``backup.TCW`` stays ``backup.TCW``, not ``backup.tcw``.

        Examples (assuming my_wallet.tcw already exists on disk):
            "my_wallet"        → "my_wallet_1.tcw"
            "my_wallet.tcw"    → "my_wallet_1.tcw"
            "my_wallet_1.tcw"  → "my_wallet_2.tcw"   (if _1 also exists)
            "new_wallet"       → "new_wallet.tcw"     (no conflict)
            "backup.TCW"       → "backup.TCW"         (no conflict, casing kept)
        """
        # 1. Ensure extension is present; remember the original suffix casing.
        if filepath.lower().endswith(".tcw"):
            # Already has extension — split it off to get stem + ext.
            stem = filepath[:-4]          # everything before ".tcw" / ".TCW"
            ext  = filepath[-4:]          # ".tcw" / ".TCW" (original casing)
        else:
            stem = filepath
            ext  = ".tcw"

        candidate = stem + ext

        # 2. No conflict → done.
        if not os.path.exists(candidate):
            return candidate

        # 3. Strip any existing trailing _N suffix from stem so that calling
        #    save("my_wallet_1") when _1 already exists produces _2, not _1_1.
        import re
        base_stem = re.sub(r"_\d+$", "", stem)

        # 4. Increment counter until a free slot is found.
        counter = 1
        while True:
            candidate = f"{base_stem}_{counter}{ext}"
            if not os.path.exists(candidate):
                return candidate
            counter += 1

    def save(self, filepath: str, password: str) -> str:
        """
        Encrypt and write the wallet to a TCW v1 file.

        The wallet MUST be unlocked to save (secrets need to be in RAM
        so they can be serialised and encrypted).

        **Extension handling** — ``.tcw`` is added automatically if omitted:
            wallet.save("my_wallet", ...)      → my_wallet.tcw
            wallet.save("my_wallet.tcw", ...)  → my_wallet.tcw  (unchanged)
            wallet.save("backup.TCW", ...)     → backup.TCW     (unchanged)

        **Collision avoidance** — if the resolved filename already exists,
        a numeric suffix is appended before the extension:
            my_wallet.tcw exists   → saves as  my_wallet_1.tcw
            my_wallet_1.tcw exists → saves as  my_wallet_2.tcw

        Args:
            filepath: Destination path.  Extension ``.tcw`` is appended
                      automatically if not present.
            password: Passphrase used to derive the AES-256 key.
                      Must be at least 8 characters.

        Returns:
            The actual path the file was written to (useful when a
            collision was resolved automatically).

        Raises:
            WalletLockedError: Wallet is locked; call unlock() first.
            ValueError:        Password is too short.
        """
        self._require_unlocked("save")
        verify_password_strength(password)

        filepath = self._normalize_filepath(filepath)
        payload  = self._to_payload()
        save_wallet(filepath, payload, password)

        # Remember the file path so unlock() can find it later.
        self._tcw_filepath = filepath
        return filepath

    # Legacy aliases for backward compatibility
    def save_to_file(self, filepath: str, password: str) -> str:
        """Alias for save(). Returns the actual path written (collision-safe)."""
        return self.save(filepath, password)

    @classmethod
    def load_from_file(cls, filepath: str, password: str) -> "Wallet":
        """
        Load and fully decrypt a TCW wallet file, returning an UNLOCKED wallet.

        This is a convenience method equivalent to:
            Wallet.load(filepath).unlock(password)

        The ``.tcw`` extension is resolved automatically if omitted
        (see :meth:`load` for details).

        Args:
            filepath:  Path to a .tcw file (extension optional).
            password:  Passphrase.

        Returns:
            UNLOCKED Wallet instance.
        """
        return cls.load(filepath).unlock(password)

    # ------------------------------------------------------------------
    # State queries
    # ------------------------------------------------------------------

    @property
    def wallet_type(self) -> str:
        """One of "hd", "xpub", "xprv"."""
        return self._wallet_type

    # ------------------------------------------------------------------
    # Basic accessors  (require UNLOCKED for secret material)
    # ------------------------------------------------------------------

    def get_private_key_hex(self) -> str:
        """Get canonical private key as hex (UNLOCKED required)."""
        self._require_unlocked("get_private_key_hex")
        if self.is_watch_only or self._private_key is None:
            raise WalletError("Private key not available in watch-only wallet")
        return self._private_key.hex()

    def get_private_key_wif(self, compressed: bool = True) -> str:
        """
        Get the canonical private key as WIF (UNLOCKED required).

        ``compressed=True`` (default) matches this wallet's public key and addresses.
        The WIF version byte is ``constants.WIF_VERSION``.
        """
        from .keys.wif import hex_to_wif

        return hex_to_wif(self.get_private_key_hex(), compressed=compressed)

    def get_public_key_hex(self) -> str:
        """Get canonical public key as hex (available while locked)."""
        return self.public_key

    def get_mnemonic(self) -> str:
        """Get mnemonic phrase (UNLOCKED required)."""
        self._require_unlocked("get_mnemonic")
        if not self._mnemonic:
            raise WalletError("Mnemonic not available for this wallet type")
        return self._mnemonic

    def get_address(
        self,
        type: str = "p2wpkh",
        script: Optional[bytes] = None,
    ) -> str:
        """
        Return an address for the current key in the requested form.

        For p2pkh: available while locked (canonical BIP-44 address stored).
        For p2wpkh: requires UNLOCKED (BIP-84 derived on-the-fly).
        For p2sh: requires UNLOCKED if no script is provided (BIP-49
                  nested SegWit, P2SH-P2WPKH, derived on-the-fly).
        For p2wsh: script= required, no unlock needed if script is provided.

        Args:
            type:   "p2pkh" | "p2wpkh" | "p2sh" | "p2wsh"  (default: p2pkh)
            script: For p2sh (optional) or p2wsh (required).

        Returns:
            Address string.
        """
        addr_type = (type or "p2pkh").lower().strip()

        if self._wallet_type == "privkey" and addr_type != "p2pkh":
            raise WalletError(
                f"get_address({addr_type!r}) is not available: this wallet "
                "was created from a raw private key (no BIP-32 chain code, "
                "so no other address types can be derived from it)."
            )

        if addr_type == "p2pkh":
            # Canonical address — already stored (BIP-44 m/44'/COIN_TYPE'/0'/0/0)
            return self.address

        if addr_type == "p2wpkh":
            # SegWit native — derived on-the-fly from BIP-84 (m/84'/COIN_TYPE'/0'/0/0)
            self._require_unlocked("get_address('p2wpkh')")
            from .keys.bip84 import derive_bip84_address_from_seed
            _, segwit_addr = derive_bip84_address_from_seed(
                self._seed, account=0, change=0, index=0
            )
            return segwit_addr

        if addr_type == "p2sh":
            if script is None:
                # Nested SegWit (P2SH-P2WPKH) — derived on-the-fly from
                # BIP-49 (m/49'/COIN_TYPE'/0'/0/0), its own purpose field,
                # separate from both BIP-44 (P2PKH) and BIP-84 (P2WPKH).
                self._require_unlocked("get_address('p2sh')")
                pubkey_bytes = self._derive_bip49_pubkey(account=0, change=0, index=0)
                return public_key_to_p2sh_segwit(pubkey_bytes)
            return script_to_p2sh_address(script)

        if addr_type == "p2wsh":
            if script is None:
                raise WalletError(
                    "get_address('p2wsh') requires script= (witness script)"
                )
            return script_to_p2wsh_address(script)

        raise WalletError(
            f"Unknown address type: {type!r}. Use p2pkh, p2wpkh, p2sh, or p2wsh."
        )

    # ------------------------------------------------------------------
    # Multisig helper
    # ------------------------------------------------------------------

    @staticmethod
    def build_multisig_script(
        m: int,
        pubkeys: List[Union[bytes, str]],
        sort_pubkeys: bool = True,
    ) -> bytes:
        """
        Build standard m-of-n multisig redeem/witness script.

        Args:
            m:           Required signatures (1..16).
            pubkeys:     33-byte compressed public keys (bytes or hex).
            sort_pubkeys: Sort for canonical form (recommended).

        Returns:
            Script bytes for get_address("p2sh", script=…) or
            get_address("p2wsh", script=…).
        """
        normalized = [
            bytes.fromhex(p) if isinstance(p, str) else p
            for p in pubkeys
        ]
        return build_multisig_script(m, normalized, sort_pubkeys=sort_pubkeys)

    # ------------------------------------------------------------------
    # Core BIP-32 API  (UNLOCKED required for xprv operations)
    # ------------------------------------------------------------------

    def get_master_xprv(self) -> str:
        """Master xprv as Base58Check string (UNLOCKED required)."""
        self._require_unlocked("get_master_xprv")
        return self._ensure_master_xprv().to_xprv()

    def get_master_xpub(self) -> str:
        """Master xpub as Base58Check string (available while locked)."""
        return self._ensure_master_xpub().to_xpub()

    def derive_xprv(self, path: str) -> str:
        """Derive xprv at path (UNLOCKED required)."""
        self._require_unlocked("derive_xprv")
        return self._ensure_master_xprv().derive_path(path).to_xprv()

    def derive_xpub(self, path: str) -> str:
        """
        Derive xpub at path.

        Full wallets: hardened or non-hardened steps.
        Watch-only:   non-hardened only.
        """
        if not path.startswith("m"):
            raise WalletError("Path must be absolute and start with 'm'")

        if not self.is_watch_only:
            self._require_unlocked("derive_xpub (hardened path)")
            return self._ensure_master_xprv().derive_path(path).to_public().to_xpub()

        master_pub = self._ensure_master_xpub()
        for index in path_to_indices(path):
            if index >= HARDENED_OFFSET:
                raise WalletError(
                    "Cannot derive hardened child from xpub-only watch-only wallet"
                )
            master_pub = master_pub.child(index)
        return master_pub.to_xpub()

    # ------------------------------------------------------------------
    # Account-level API (BIP-44 / BIP-49 / BIP-84)
    # ------------------------------------------------------------------
    #
    # Each address type has its own, fully independent purpose field and
    # therefore its own account path:
    #   P2PKH            (legacy)        -> m/44'/COIN_TYPE'/account'
    #   P2SH-P2WPKH      (nested SegWit) -> m/49'/COIN_TYPE'/account'
    #   P2WPKH           (native SegWit) -> m/84'/COIN_TYPE'/account'
    #
    # get_account_xprv/get_account_xpub default to the BIP-84 path for
    # backward compatibility with existing callers, but accept an
    # explicit `purpose` to reach the BIP-44 or BIP-49 branch instead.
    # The bip44_account_path/bip49_account_path/_account_path helpers
    # never fall back on one another's purpose value.

    def _account_path(self, account: int, purpose: int = BIP84_PURPOSE) -> str:
        return f"m/{purpose}'/{COIN_TYPE}'/{account}'"

    def get_account_xprv(self, account: int, purpose: int = BIP84_PURPOSE) -> str:
        """
        Account xprv at m/{purpose}'/COIN_TYPE'/account' (UNLOCKED required).

        `purpose` defaults to 84 (native SegWit) for backward
        compatibility. Pass BIP44_PURPOSE (44) or BIP49_PURPOSE (49)
        explicitly for the legacy P2PKH or nested-SegWit account branch.
        """
        return self.derive_xprv(self._account_path(account, purpose))

    def get_account_xpub(self, account: int, purpose: int = BIP84_PURPOSE) -> str:
        """
        Account xpub at m/{purpose}'/COIN_TYPE'/account'.

        `purpose` defaults to 84 (native SegWit) for backward
        compatibility. Pass BIP44_PURPOSE (44) or BIP49_PURPOSE (49)
        explicitly for the legacy P2PKH or nested-SegWit account branch.
        """
        return self.derive_xpub(self._account_path(account, purpose))

    def get_account_xprv_p2pkh(self, account: int = 0) -> str:
        """BIP-44 account xprv at m/44'/COIN_TYPE'/account' (UNLOCKED required)."""
        return self.derive_xprv(bip44_account_path(account))

    def get_account_xpub_p2pkh(self, account: int = 0) -> str:
        """BIP-44 account xpub at m/44'/COIN_TYPE'/account'."""
        return self.derive_xpub(bip44_account_path(account))

    def get_account_xprv_p2sh_segwit(self, account: int = 0) -> str:
        """BIP-49 account xprv at m/49'/COIN_TYPE'/account' (UNLOCKED required)."""
        return self.derive_xprv(bip49_account_path(account))

    def get_account_xpub_p2sh_segwit(self, account: int = 0) -> str:
        """BIP-49 account xpub at m/49'/COIN_TYPE'/account'."""
        return self.derive_xpub(bip49_account_path(account))

    # ------------------------------------------------------------------
    # Address derivation
    # ------------------------------------------------------------------

    def derive_address(
        self, account: int = 0, change: int = 0, index: int = 0
    ) -> Tuple[str, str]:
        """
        Derive BIP-84 address at specific path (UNLOCKED required).

        Returns:
            (private_key_hex, address)
        """
        self._require_unlocked("derive_address")
        if self.is_watch_only:
            raise WalletError("Cannot derive private addresses from watch-only wallet")

        from .keys.bip84 import derive_bip84_address_from_seed

        private_key, address = derive_bip84_address_from_seed(
            self._seed, account, change, index
        )
        return private_key.hex(), address

    def get_next_address(self, change: int = 0) -> Tuple[str, str]:
        """
        Increment address index and return the next address (UNLOCKED required).

        Returns:
            (private_key_hex, address)
        """
        self._require_unlocked("get_next_address")
        if self.is_watch_only:
            raise WalletError("Cannot derive next address from watch-only wallet")

        if change == 0:
            self.address_index += 1
        else:
            self.change_index += 1

        return self.derive_address(
            self.account_index,
            change,
            self.address_index if change == 0 else self.change_index,
        )

    def derive_address_from_xpub(self, change: int, index: int) -> str:
        """
        Derive address from the wallet's base xpub (watch-only safe).

        The stored xpub is treated as root; change/index is derived
        relative to it.
        """
        base_xpub = self._ensure_master_xpub()
        child_pub  = base_xpub.derive_path(f"{change}/{index}").key
        return public_key_to_segwit_v0(child_pub)

    # ------------------------------------------------------------------
    # Generic export / import for xpub / xprv
    # ------------------------------------------------------------------

    def export_xpub(self, path: str) -> str:
        """Export xpub at arbitrary BIP-32 path."""
        return self.derive_xpub(path)

    def export_xprv(self, path: str) -> str:
        """Export xprv at arbitrary BIP-32 path (UNLOCKED required)."""
        return self.derive_xprv(path)

    def import_xpub(self, xpub: str) -> None:
        """Import external xpub as the wallet's base xpub for watch-only derivation."""
        ext_pub           = ExtendedPublicKey.from_xpub(xpub)
        self._master_xpub = ext_pub
        self._imported_xpub = xpub

    def import_xprv(self, xprv: str) -> None:
        """Import external xprv (UNLOCKED required for secret storage)."""
        self._require_unlocked("import_xprv")
        ext_priv              = ExtendedPrivateKey.from_xprv(xprv)
        self._master_xprv     = ext_priv
        self._master_xpub     = ext_priv.to_public()
        self._imported_xprv   = xprv
        self._imported_xpub   = self._master_xpub.to_xpub()
        self.is_watch_only    = False

    # ------------------------------------------------------------------
    # ESP32 bridge (Extract to ESP / Import from ESP)
    # ------------------------------------------------------------------
    #
    # See wallet_storage/esp_bridge.py and ESP_WALLET_STRUCTURE.md for the
    # full design. Ciphertext bytes are never copied directly between the
    # two formats (different KDF/AAD/key) — both directions go through
    # the shared plaintext payload.

    def export_to_esp_blob(
        self,
        esp_password: str,
        iterations: int = None,
        totp: Optional[List[str]] = None,
        totp_mask: Optional[int] = None,
        passphrase_used: Optional[bool] = None,
    ) -> bytes:
        """
        Encrypt this wallet's secret material as a TCE1 blob for the
        ESP32 (UNLOCKED required).

        Only "hd" wallets (mnemonic + seed) and "privkey" wallets (a
        single raw imported key, e.g. from Wallet.from_private_key())
        can be exported — "xprv" and "xpub" wallets are rejected with a
        clear error (see tcw_payload_to_esp_payload).

        Args:
            esp_password:    Password to protect the ESP blob (may differ
                             from this wallet's own .tcw password, if any).
            iterations:      PBKDF2 iteration count, 1..10000. Defaults to
                             the ESP32 ceiling.
            totp:            Optional 2FA slots to embed.
            totp_mask:       Optional 2FA slot-enabled bitmask.
            passphrase_used: Optional BIP-39 25th-word flag to embed.

        Returns:
            Raw TCE1 blob bytes (send blob.hex() to the ESP32's
            POST /api/wallet/import).
        """
        self._require_unlocked("export_to_esp_blob")
        from .wallet_storage.esp_bridge import tcw_payload_to_esp_payload, validate_esp_payload
        from .wallet_storage.tce import encrypt_esp_blob
        from .wallet_storage.kdf import PBKDF2_MAX_ITERATIONS

        if iterations is None:
            iterations = PBKDF2_MAX_ITERATIONS

        tcw_payload = self._to_payload()
        esp_payload = tcw_payload_to_esp_payload(
            tcw_payload, totp=totp, totp_mask=totp_mask, passphrase_used=passphrase_used
        )
        validate_esp_payload(esp_payload)
        return encrypt_esp_blob(esp_payload, esp_password, iterations=iterations)

    @classmethod
    def import_from_esp_blob(cls, blob: bytes, esp_password: str) -> "Wallet":
        """
        Decrypt a TCE1 blob exported from the ESP32 and build an
        UNLOCKED Wallet from it directly (no intermediate .tcw file).

        The result is wallet_type "hd" (if the ESP wallet was HD) or
        "privkey" (if it was a raw imported key), mirroring the ESP
        firmware's own wallet_type field exactly.

        Args:
            blob:         Raw TCE1 bytes read from the ESP32's
                          GET /api/wallet/export.
            esp_password: The password protecting the ESP wallet.

        Returns:
            UNLOCKED Wallet instance.

        Raises:
            TCEAuthError:   Wrong esp_password, or the blob is
                            corrupted/tampered.
            TCEFormatError: blob is not a valid TCE1 container.
            ESPBridgeError: Decrypted payload is malformed or inconsistent.
        """
        from .wallet_storage.tce import decrypt_esp_blob
        from .wallet_storage.esp_bridge import validate_esp_payload, esp_payload_to_tcw_payload

        esp_payload = decrypt_esp_blob(blob, esp_password)
        validate_esp_payload(esp_payload)
        tcw_payload = esp_payload_to_tcw_payload(esp_payload)

        w = cls()
        w._locked = False
        w._load_from_payload(tcw_payload)
        return w

    # ------------------------------------------------------------------
    # Serialisation  (internal)
    # ------------------------------------------------------------------

    def _to_payload(self) -> Dict:
        """
        Build the dict that goes into the encrypted TCW payload.

        All secret fields are included.  Public fields are included too
        for full restore without re-derivation, and for privacy (no
        metadata leaks even for xpub).
        """
        self._require_unlocked("_to_payload")
        return {
            "format":          "TCW",
            "version":         1,
            "wallet_type":     self._wallet_type,
            # --- secret material ---
            "mnemonic":        self._mnemonic,
            "seed_hex":        self._seed.hex() if self._seed else None,
            "imported_xprv":   self._imported_xprv,
            "raw_private_key_hex": (
                self._private_key.hex()
                if self._wallet_type == "privkey" and self._private_key else None
            ),
            # --- public material (kept inside payload for privacy) ---
            "imported_xpub":   self._imported_xpub,
            "address":         self.address,
            "public_key":      self.public_key,
            "derivation_path": self.derivation_path,
            "account_index":   self.account_index,
            "change_index":    self.change_index,
            "address_index":   self.address_index,
            "is_watch_only":   self.is_watch_only,
        }

    def _load_from_payload(self, payload: Dict) -> None:
        """
        Restore wallet state from a decrypted TCW payload dict.
        Called by unlock() after successful decryption.
        """
        fmt = payload.get("format")
        if fmt != "TCW":
            raise WalletError(f"Unexpected payload format: {fmt!r}")

        wallet_type = payload.get("wallet_type", "hd")
        self._wallet_type    = wallet_type
        self.is_watch_only   = payload.get("is_watch_only", False)
        self.address         = payload.get("address", "")
        self.public_key      = payload.get("public_key", "")
        self.derivation_path = payload.get("derivation_path", "")
        self.account_index   = payload.get("account_index", 0)
        self.change_index    = payload.get("change_index", 0)
        self.address_index   = payload.get("address_index", 0)
        self._imported_xpub  = payload.get("imported_xpub")

        # Restore public extended key (not secret)
        if self._imported_xpub:
            self._master_xpub = ExtendedPublicKey.from_xpub(self._imported_xpub)

        # Restore secret material
        mnemonic = payload.get("mnemonic")
        seed_hex = payload.get("seed_hex")
        imp_xprv = payload.get("imported_xprv")

        if wallet_type == "hd":
            from .keys.ec import privkey_to_pubkey as _privkey_to_pubkey
            _bip44_path = f"m/{BIP44_PURPOSE}'/{COIN_TYPE}'/0'/0/0"

            if mnemonic:
                self._mnemonic = mnemonic
                self._seed     = bytes.fromhex(seed_hex) if seed_hex else mnemonic_to_seed(mnemonic)
            elif seed_hex:
                self._seed = bytes.fromhex(seed_hex)
            else:
                raise WalletError("HD wallet payload is missing mnemonic and seed")

            # Canonical key: BIP-44 P2PKH (m/44'/COIN_TYPE'/0'/0/0)
            priv, _ = derive_path_from_seed(self._seed, _bip44_path)
            pub     = _privkey_to_pubkey(priv, compressed=True)
            addr    = pubkey_to_p2pkh_address(pub)
            self._private_key = priv
            self.public_key   = pub.hex()
            self.address      = addr
            # Lazily derive master keys on demand

        elif wallet_type == "xprv":
            if not imp_xprv:
                raise WalletError("xprv wallet payload is missing imported_xprv")
            self._imported_xprv = imp_xprv
            ext_priv            = ExtendedPrivateKey.from_xprv(imp_xprv)
            self._master_xprv   = ext_priv
            self._master_xpub   = ext_priv.to_public()
            child_priv          = ext_priv.derive_path("0/0")
            self._private_key   = child_priv.key

        elif wallet_type == "privkey":
            raw_hex = payload.get("raw_private_key_hex")
            if not raw_hex:
                raise WalletError("privkey wallet payload is missing raw_private_key_hex")
            from .keys.ec import privkey_to_pubkey as _privkey_to_pubkey
            self._private_key = bytes.fromhex(raw_hex)
            pub = _privkey_to_pubkey(self._private_key, compressed=True)
            self.public_key = pub.hex()
            self.address    = pubkey_to_p2pkh_address(pub)
            # No chain code was ever provided for a raw imported key, so
            # there is no master xprv/xpub to reconstruct here.

        elif wallet_type == "xpub":
            # Watch-only: no secret material to restore
            pass

        else:
            raise WalletError(f"Unknown wallet_type in payload: {wallet_type!r}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_unlocked(self, operation: str = "") -> None:
        if self._locked:
            op_str = f" for '{operation}'" if operation else ""
            raise WalletLockedError(
                f"Wallet is locked{op_str}. Call unlock(password) first."
            )

    def _ensure_master_xprv(self) -> ExtendedPrivateKey:
        if self.is_watch_only:
            raise WalletError("Master xprv not available in watch-only wallet")
        if self._wallet_type == "privkey":
            raise WalletError(
                "Master xprv not available: this wallet was created from a "
                "raw private key (no BIP-32 chain code, no HD tree)."
            )
        if self._master_xprv is None:
            if self._seed is None:
                raise WalletLockedError(
                    "Seed not available. Call unlock(password) first."
                )
            self._master_xprv = ExtendedPrivateKey.from_seed(self._seed)
        return self._master_xprv

    def _ensure_master_xpub(self) -> ExtendedPublicKey:
        if self._master_xpub is not None:
            return self._master_xpub

        if self._wallet_type == "privkey":
            raise WalletError(
                "Master xpub not available: this wallet was created from a "
                "raw private key (no BIP-32 chain code, no HD tree)."
            )

        if self._master_xprv is not None:
            self._master_xpub = self._master_xprv.to_public()
        elif not self.is_watch_only:
            if self._seed is None:
                raise WalletLockedError(
                    "Seed not available. Call unlock(password) first."
                )
            self._master_xprv = ExtendedPrivateKey.from_seed(self._seed)
            self._master_xpub = self._master_xprv.to_public()
        else:
            raise WalletError("No xpub available for this wallet")

        return self._master_xpub

    def _derive_bip44_pubkey(
        self, account: int = 0, change: int = 0, index: int = 0
    ) -> bytes:
        """
        Derive compressed public key at m/44'/COIN_TYPE'/account'/change/index.
        Requires UNLOCKED state (seed needed).
        """
        if not self._seed:
            raise WalletLockedError(
                "Seed not available. Call unlock(password) first."
            )
        from .keys.ec import privkey_to_pubkey

        path = f"m/{BIP44_PURPOSE}'/{COIN_TYPE}'/{account}'/{change}/{index}"
        private_key, _ = derive_path_from_seed(self._seed, path)
        return privkey_to_pubkey(private_key, compressed=True)

    def _derive_bip49_pubkey(
        self, account: int = 0, change: int = 0, index: int = 0
    ) -> bytes:
        """
        Derive compressed public key at m/49'/COIN_TYPE'/account'/change/index.
        Requires UNLOCKED state (seed needed).

        Kept fully separate from _derive_bip44_pubkey (purpose 44') and
        from the BIP-84 path (purpose 84') — BIP-49 has its own purpose
        field and must not "drive on 84'".
        """
        if not self._seed:
            raise WalletLockedError(
                "Seed not available. Call unlock(password) first."
            )
        from .keys.ec import privkey_to_pubkey

        path = f"m/{BIP49_PURPOSE}'/{COIN_TYPE}'/{account}'/{change}/{index}"
        private_key, _ = derive_path_from_seed(self._seed, path)
        return privkey_to_pubkey(private_key, compressed=True)

    # ------------------------------------------------------------------
    # HASHLOCK (C2) spending
    # ------------------------------------------------------------------

    def _candidate_keys(self, account: int = 0, change: int = 0, index: int = 0) -> List[bytes]:
        """
        Private keys this wallet can offer for signing / decrypting: the canonical key plus
        (seed wallets) the BIP-84 and BIP-44 keys at m/<purpose>'/COIN_TYPE'/account'/change/index.
        Callers match them against an output script or try them in order; they never guess.
        """
        keys: List[bytes] = []
        if self._private_key:
            keys.append(self._private_key)
        if self._seed:
            for purpose in (BIP84_PURPOSE, BIP44_PURPOSE):
                path = f"m/{purpose}'/{COIN_TYPE}'/{account}'/{change}/{index}"
                key, _ = derive_path_from_seed(self._seed, path)
                if key not in keys:
                    keys.append(key)
        return keys

    def _find_hashlock_key(
        self, owner_hash: bytes, account: int, change: int, index: int
    ) -> bytes:
        """
        Return the private key whose HASH160(pubkey) equals ``owner_hash``.

        Candidates: the canonical key, plus (seed wallets) the BIP-84 and BIP-44
        keys at m/<purpose>'/COIN_TYPE'/account'/change/index. A key is only used
        when it provably owns the UTXO.
        """
        from .keys.ec import privkey_to_pubkey
        from .utils import hash160

        for key in self._candidate_keys(account, change, index):
            if hash160(privkey_to_pubkey(key, compressed=True)) == owner_hash:
                return key

        from .transaction.hashlock import HashlockSpendSigningError
        raise HashlockSpendSigningError(
            "No key of this wallet owns the HASHLOCK UTXO "
            f"(searched account={account}, change={change}, index={index}). "
            "Pass the account/change/index the funds were sent to."
        )

    def sign_hashlock_spend(
        self,
        tx,
        input_index: int,
        utxo: dict,
        secret: Union[str, bytes],
        *,
        account: int = 0,
        change: int = 0,
        index: int = 0,
    ):
        """
        Sign input ``input_index`` of ``tx`` as a HASHLOCK (C2) spend (UNLOCKED required).

        Verifies the secret against the UTXO's secret_hash, finds the wallet key that
        owns the UTXO, signs, and places [sig, pubkey, preimage] in the witness
        (P2WPKH owner) or <sig> <pubkey> <preimage> in the scriptSig (P2PKH owner).
        ``tx`` is modified in place and also returned.

        Args:
            tx:          unsigned Transaction (e.g. from build_hashlock_spend).
            input_index: which input spends the C2 UTXO.
            utxo:        dict with txid, vout, value, script_pubkey, secret_hash.
            secret:      TCS secret / free-form text (str) or raw preimage (bytes).
            account, change, index: HD position of the owning key (seed wallets).
        """
        from .transaction.hashlock import normalize_hashlock_utxo, sign_hashlock_input

        self._require_unlocked("sign_hashlock_spend")
        if self.is_watch_only:
            raise WalletError("Cannot sign with a watch-only wallet")
        owner = normalize_hashlock_utxo(utxo)
        key = self._find_hashlock_key(owner.owner_hash, account, change, index)
        return sign_hashlock_input(tx, input_index, utxo, key, secret)

    def spend_hashlock(
        self,
        utxo: dict,
        destination: str,
        amount: Optional[int] = None,
        fee: Optional[int] = None,
        secret: Union[str, bytes, None] = None,
        *,
        fee_rate: Optional[int] = None,
        change_address: Optional[str] = None,
        account: int = 0,
        change: int = 0,
        index: int = 0,
    ):
        """
        Spend a HASHLOCK (C2) UTXO end to end (UNLOCKED required):
        validate -> verify secret -> build -> sign -> finalize.

        Returns a HashlockSpendResult; ``result.raw_transaction`` is the hex to broadcast.
        See transaction.hashlock.build_hashlock_spend for amount / fee / change rules.

            with wallet.unlocked(password):
                result = wallet.spend_hashlock(utxo, destination, secret=tcs_secret)
        """
        from .transaction.hashlock import (
            HashlockSpendResult,
            InvalidHashlockSecretError,
            build_hashlock_spend,
            finalize_hashlock_spend,
            normalize_hashlock_utxo,
        )

        self._require_unlocked("spend_hashlock")
        if self.is_watch_only:
            raise WalletError("Cannot sign with a watch-only wallet")
        if secret is None:
            raise InvalidHashlockSecretError("secret is required to spend a HASHLOCK UTXO")

        u = normalize_hashlock_utxo(utxo)
        tx = build_hashlock_spend(
            utxo, destination, amount=amount, fee=fee, secret=secret,
            fee_rate=fee_rate, change_address=change_address,
        )
        self.sign_hashlock_spend(
            tx, 0, utxo, secret, account=account, change=change, index=index
        )
        raw = finalize_hashlock_spend(tx)

        total_out = sum(o.value for o in tx.vout)
        sent = tx.vout[0].value
        return HashlockSpendResult(
            tx=tx,
            raw_transaction=raw,
            txid=tx.txid(),
            fee=u.value - total_out,
            amount=sent,
            change=total_out - sent,
            secret_hash=u.secret_hash.hex(),
        )

    # ------------------------------------------------------------------
    # TMSG (Tencoin Message): encrypted messages
    # ------------------------------------------------------------------

    def tmsg_public_key(
        self,
        address_type: str = "p2wpkh",
        account: int = 0,
        change: int = 0,
        index: int = 0,
    ) -> str:
        """
        Compressed public key (66 hex chars) that others encrypt TMSG messages to.

        Give it to people who want to write to you, or let them find it on-chain with
        ``rpc.get_public_key(address)`` once that address has spent an output. The key
        belongs to the address of the same type: "p2wpkh" -> tc1q..., "p2pkh" -> T...
        (UNLOCKED required; seed wallets can pass account/change/index).
        """
        from .tmsg.keys import public_key_from_private_key

        self._require_unlocked("tmsg_public_key")
        kind = (address_type or "p2wpkh").lower().strip()
        if kind not in ("p2wpkh", "p2pkh"):
            raise WalletError("address_type must be 'p2wpkh' or 'p2pkh'")
        if not self._seed:
            if kind == "p2wpkh":
                raise WalletError("p2wpkh keys need a seed wallet; this wallet only has a raw key")
            key = self._private_key
        else:
            purpose = BIP84_PURPOSE if kind == "p2wpkh" else BIP44_PURPOSE
            key, _ = derive_path_from_seed(
                self._seed, f"m/{purpose}'/{COIN_TYPE}'/{account}'/{change}/{index}"
            )
        return public_key_from_private_key(key).hex()

    def _tmsg_utxos(self, rpc) -> List[dict]:
        """Spendable UTXOs of the wallet's own addresses (P2PKH, and P2WPKH for seed wallets)."""
        from .transaction.address import address_to_script

        addresses = [self.address]
        if self._seed:
            addresses.append(self.get_address("p2wpkh"))
        utxos: List[dict] = []
        for addr in addresses:
            for u in rpc.list_unspent(addr):
                utxos.append({
                    "txid": u["txid"], "vout": u["vout"], "amount": u["amount"],
                    "script_pubkey": address_to_script(addr), "address": addr,
                })
        return utxos

    def send_tmsg(
        self,
        rpc,
        to_address: str,
        message: Union[str, bytes],
        recipients=None,
        *,
        amount: int = 1,
        fee: Optional[int] = None,
        fee_rate: Optional[int] = None,
        change_address: Optional[str] = None,
        include_self: bool = False,
        size_policy: str = "error",
        utxos: Optional[List[dict]] = None,
        broadcast: bool = False,
        account: int = 0,
        change: int = 0,
        index: int = 0,
    ):
        """
        Send an encrypted on-chain message (UNLOCKED required).

        Output 0 pays ``amount`` Tenos (default 1, the dust limit does not apply) to
        ``to_address``; output 1 is an OP_RETURN with the encrypted TMSG; output 2 is the change.

        Args:
            rpc:            RPCClient (UTXOs, public-key lookup, optional broadcast).
            to_address:     recipient address.
            message:        text or bytes. Up to 958 bytes for one recipient.
            recipients:     public key(s) allowed to decrypt. None = the on-chain key of
                            ``to_address`` (needs that address to have spent before).
            include_self:   also encrypt to this wallet so you can read your own message
                            (makes it a v2 message: 93 bytes more overhead).
            change_address: default = this wallet's P2PKH address.
            utxos:          use these UTXOs instead of asking ``rpc`` (dicts with txid, vout,
                            amount, scriptPubKey). For keys beyond account/change/index 0 pass
                            those indexes.
            broadcast:      True = also send it with ``rpc.send_raw_transaction``.

        Returns:
            TMSGTransaction (already signed; ``.raw_transaction``, ``.txid``, ``.fee``).
            With ``broadcast=True`` its ``broadcast_txid`` is set.
        """
        from .tmsg.keys import parse_public_keys, public_key_from_private_key
        from .tmsg.onchain import build_tmsg_transaction

        self._require_unlocked("send_tmsg")
        if self.is_watch_only:
            raise WalletError("Cannot sign with a watch-only wallet")

        if utxos is None:
            utxos = self._tmsg_utxos(rpc)
        if not utxos:
            raise WalletError("no spendable UTXOs found for this wallet")

        keys = parse_public_keys(recipients if recipients is not None else to_address, rpc=rpc)
        if include_self:
            own = public_key_from_private_key(self._private_key)
            if own not in keys:
                keys.append(own)

        tx = build_tmsg_transaction(
            utxos, to_address, message, recipients=keys,
            amount=amount, fee=fee, fee_rate=fee_rate,
            change_address=change_address or self.address,
            rpc=rpc, size_policy=size_policy,
        )
        tx.sign(self._candidate_keys(account, change, index))
        if broadcast:
            tx.broadcast_txid = rpc.send_raw_transaction(tx.raw_transaction)
        return tx

    def decrypt_tmsg(
        self,
        payload: Union[bytes, str],
        *,
        account: int = 0,
        change: int = 0,
        index: int = 0,
    ) -> bytes:
        """
        Decrypt a raw TMSG payload (bytes or hex) with this wallet's keys (UNLOCKED required).

        Tries the canonical key and the BIP-84 / BIP-44 keys at account/change/index.
        Raises TMSGDecryptionError if none opens it.
        """
        from .tmsg.crypto import decrypt

        self._require_unlocked("decrypt_tmsg")
        return decrypt(payload, self._candidate_keys(account, change, index))

    def decrypt_tmsg_transaction(
        self,
        source,
        *,
        rpc=None,
        account: int = 0,
        change: int = 0,
        index: int = 0,
    ):
        """
        Decrypt the TMSG(s) inside a transaction (Transaction, raw hex, or txid with ``rpc``).

        Returns a list of DecryptedMessage (``.output_index``, ``.plaintext``, ``.text``).
        """
        from .tmsg.onchain import decrypt_transaction

        self._require_unlocked("decrypt_tmsg_transaction")
        return decrypt_transaction(source, self._candidate_keys(account, change, index), rpc=rpc)

    # ------------------------------------------------------------------
    # Internal constructor helper
    # ------------------------------------------------------------------

    @classmethod
    def _from_seed(cls, seed: bytes, mnemonic: str = "") -> "Wallet":
        """Build an UNLOCKED HD wallet from a raw seed (canonical: BIP-44 P2PKH)."""
        if len(seed) != 64:
            raise WalletError(f"Invalid seed length: {len(seed)}")

        from .keys.ec import privkey_to_pubkey

        w = cls()
        w._wallet_type    = "hd"
        w._seed           = seed
        w._mnemonic       = mnemonic
        w.derivation_path = DERIVATION_PATH  # m/44'/5353'/0'/0/0
        w.account_index   = 0
        w.change_index    = 0
        w.address_index   = 0
        w.is_watch_only   = False
        w._locked         = False

        # Canonical key: BIP-44 P2PKH (m/44'/COIN_TYPE'/0'/0/0)
        path = f"m/{BIP44_PURPOSE}'/{COIN_TYPE}'/0'/0/0"
        priv, _ = derive_path_from_seed(seed, path)
        pub = privkey_to_pubkey(priv, compressed=True)
        addr = pubkey_to_p2pkh_address(pub)

        w._private_key = priv
        w.public_key   = pub.hex()
        w.address      = addr

        return w

    # ------------------------------------------------------------------
    # repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        state = "LOCKED" if self._locked else "UNLOCKED"
        wtype = self._wallet_type
        addr  = self.address or "(unknown)"
        return f"<Wallet type={wtype!r} state={state} address={addr!r}>"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _zeroize_attr(obj: object, attr: str) -> None:
    """
    Best-effort zeroization of a bytes/bytearray attribute.

    In CPython, bytes objects are immutable, so we can only delete the
    reference.  bytearray objects can be overwritten in-place.
    """
    value = getattr(obj, attr, None)
    if isinstance(value, bytearray):
        for i in range(len(value)):
            value[i] = 0
    # For plain bytes, we can only unlink; the GC decides when memory is freed.
    setattr(obj, attr, None)
"""
Off-chain TMSG: text messages, files, folders and ZIP archives.

Everything is a thin layer over ``crypto.encrypt`` / ``crypto.decrypt``:

    encrypt_text / decrypt_text      text <-> payload (bytes or hex)
    encrypt_file / decrypt_file      file.ext  <->  file.ext.enc
    encrypt_folder / decrypt_folder  folder or .zip  <->  .zip.enc archive  OR  <folder>_enc/ tree

The whole plaintext is processed in memory (the format is a single AEAD message), so
files are limited to ``DEFAULT_MAX_FILE_SIZE`` unless you raise ``max_size``.
Existing files are never overwritten unless ``overwrite=True``: without it a numbered
name (``name_1.ext``) is used, like the reference tools.

Decrypting a folder is safe against hostile archives: anyone can encrypt to your public
key, so entries with absolute paths, ``..``, drive letters or links are refused and the
amount of extracted data is capped.
"""

import io
import os
import stat
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, List, Optional, Tuple, Union

from . import crypto
from .errors import TMSGError, TMSGFormatError, TMSGSizeError
from .keys import PrivateKeyLike, PublicKeyLike, parse_public_keys

PathLike = Union[str, "os.PathLike[str]"]

DEFAULT_MAX_FILE_SIZE = 1024 ** 3            # 1 GiB per file / archive
DEFAULT_MAX_EXTRACT_SIZE = 4 * 1024 ** 3     # 4 GiB written by one folder decryption
DEFAULT_MAX_ARCHIVE_FILES = 100_000
ENC_SUFFIX = ".enc"
ARCHIVE_SUFFIX = ".zip.enc"


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FileResult:
    path: Path               # file that was written
    input_size: int
    output_size: int
    version: int             # TMSG version of the payload
    recipients: int


@dataclass
class FolderResult:
    output: Path                                  # output file (archive mode) or folder
    mode: str                                     # "archive" | "files" | "extract" | "decrypt-files"
    files: int = 0                                # files processed successfully
    input_size: int = 0
    output_size: int = 0
    version: Optional[int] = None
    recipients: Optional[int] = None
    errors: List[Tuple[str, str]] = field(default_factory=list)    # (name, reason)
    skipped: List[Tuple[str, str]] = field(default_factory=list)   # (name, reason)

    @property
    def ok(self) -> bool:
        return not self.errors


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------

def encrypt_text(
    text: str,
    recipients: Union[PublicKeyLike, Iterable[PublicKeyLike]],
    *,
    as_hex: bool = False,
    rpc: Any = None,
) -> Union[bytes, str]:
    """
    Encrypt a text message (UTF-8) and return the TMSG payload (bytes, or hex if ``as_hex``).
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be str, got {type(text).__name__}")
    payload = crypto.encrypt(text.encode("utf-8"), recipients, rpc=rpc)
    return payload.hex() if as_hex else payload


def decrypt_text(
    payload: Union[bytes, bytearray, str],
    private_keys: Union[PrivateKeyLike, Iterable[PrivateKeyLike]],
) -> str:
    """
    Decrypt a payload (bytes or hex) to text.

    Raises:
        TMSGFormatError: the plaintext is not valid UTF-8 (use ``crypto.decrypt`` for binary).
    """
    plaintext = crypto.decrypt(payload, private_keys)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        raise TMSGFormatError(
            "the decrypted data is not UTF-8 text; use tmsg.decrypt() to get the raw bytes"
        ) from None


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    base, ext = os.path.splitext(str(path))
    counter = 1
    while os.path.exists(f"{base}_{counter}{ext}"):
        counter += 1
    return Path(f"{base}_{counter}{ext}")


def _choose_output(default: Path, output: Optional[PathLike], overwrite: bool) -> Path:
    if output is None:
        return default if overwrite else _unique_path(default)
    out = Path(output)
    if out.exists() and not overwrite:
        raise FileExistsError(f"{out} already exists (pass overwrite=True to replace it)")
    return out


def _write_atomic(path: Path, data: bytes) -> None:
    """Write via a temp file in the same directory, then rename into place."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmsg-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_limited(path: Path, max_size: int) -> bytes:
    size = path.stat().st_size
    if size > max_size:
        raise TMSGSizeError(
            f"{path.name} is {size} bytes; the limit is {max_size} (raise max_size= to allow it)",
            size=size, limit=max_size,
        )
    return path.read_bytes()


def _strip_enc(path: Path) -> Path:
    return path.with_name(path.name[:-len(ENC_SUFFIX)]) if path.name.endswith(ENC_SUFFIX) \
        else path.with_name(path.name + ".dec")


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

def encrypt_file(
    path: PathLike,
    recipients: Union[PublicKeyLike, Iterable[PublicKeyLike]],
    output: Optional[PathLike] = None,
    *,
    overwrite: bool = False,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
    rpc: Any = None,
) -> FileResult:
    """
    Encrypt one file. ``report.pdf`` -> ``report.pdf.enc`` (next to it unless ``output``).
    """
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(f"file not found: {src}")
    data = _read_limited(src, max_size)
    payload = crypto.encrypt(data, recipients, rpc=rpc)
    out = _choose_output(src.with_name(src.name + ENC_SUFFIX), output, overwrite)
    _write_atomic(out, payload)
    info = crypto.inspect(payload)
    return FileResult(out, len(data), len(payload), info.version, info.recipients)


def decrypt_file(
    path: PathLike,
    private_keys: Union[PrivateKeyLike, Iterable[PrivateKeyLike]],
    output: Optional[PathLike] = None,
    *,
    overwrite: bool = False,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
) -> FileResult:
    """
    Decrypt one ``.enc`` file. ``report.pdf.enc`` -> ``report.pdf`` (``.dec`` is appended
    when the name does not end in ``.enc``).
    """
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(f"file not found: {src}")
    payload = _read_limited(src, max_size)
    info = crypto.inspect(payload)
    plaintext = crypto.decrypt(payload, private_keys)
    out = _choose_output(_strip_enc(src), output, overwrite)
    _write_atomic(out, plaintext)
    return FileResult(out, len(payload), len(plaintext), info.version, info.recipients)


# ---------------------------------------------------------------------------
# Folders / ZIP
# ---------------------------------------------------------------------------

def _folder_to_zip_bytes(folder: Path, skipped: List[Tuple[str, str]]) -> bytes:
    """Zip a folder in memory (deterministic order, top folder name kept, symlinks skipped)."""
    folder = folder.resolve()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(folder):
            dirs.sort()
            for name in sorted(files):
                full = Path(root) / name
                rel = full.relative_to(folder.parent).as_posix()
                if full.is_symlink() or not full.is_file():
                    skipped.append((rel, "not a regular file (symlink or special file)"))
                    continue
                zf.write(full, rel)
    return buf.getvalue()


def encrypt_folder(
    path: PathLike,
    recipients: Union[PublicKeyLike, Iterable[PublicKeyLike]],
    output: Optional[PathLike] = None,
    *,
    mode: str = "archive",
    overwrite: bool = False,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
    rpc: Any = None,
) -> FolderResult:
    """
    Encrypt a folder (or an existing .zip file).

    mode="archive"  zip the folder in memory and encrypt it once -> ``<name>.zip.enc``
                    (file names and structure are hidden). An input .zip is encrypted as is.
    mode="files"    encrypt every file separately -> ``<name>_enc/`` with the same structure
                    and ``.enc`` appended to every file name (names stay visible).

    Symlinks and special files are skipped and listed in ``result.skipped``.
    In "files" mode a failing file does not stop the others; see ``result.errors``.
    """
    if mode not in ("archive", "files"):
        raise ValueError("mode must be 'archive' or 'files'")
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(f"path not found: {src}")
    is_zip = src.is_file()
    if is_zip and not zipfile.is_zipfile(src):
        raise TMSGFormatError(f"{src.name} is a file but not a ZIP archive; use encrypt_file()")

    keys = parse_public_keys(recipients, rpc=rpc)       # resolve once, reuse for every file
    src_abs = src.resolve()

    # ── archive ─────────────────────────────────────────────────────────────
    if mode == "archive":
        skipped: List[Tuple[str, str]] = []
        if is_zip:
            data = _read_limited(src_abs, max_size)
            base = src_abs.stem
        else:
            data = _folder_to_zip_bytes(src_abs, skipped)
            base = src_abs.name
        if len(data) > max_size:
            raise TMSGSizeError(f"archive is {len(data)} bytes; the limit is {max_size}",
                                size=len(data), limit=max_size)
        payload = crypto.encrypt(data, keys)
        out = _choose_output(src_abs.parent / f"{base}{ARCHIVE_SUFFIX}", output, overwrite)
        _write_atomic(out, payload)
        info = crypto.inspect(payload)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            count = sum(1 for i in zf.infolist() if not i.filename.endswith("/"))
        return FolderResult(out, "archive", files=count, input_size=len(data),
                            output_size=len(payload), version=info.version,
                            recipients=info.recipients, skipped=skipped)

    # ── one file at a time ──────────────────────────────────────────────────
    base = src_abs.stem if is_zip else src_abs.name
    out_root = _choose_output(src_abs.parent / f"{base}_enc", output, overwrite)
    result = FolderResult(out_root, "files")

    def _one(rel: str, data: bytes) -> None:
        payload = crypto.encrypt(data, keys)
        dst = out_root / (rel + ENC_SUFFIX)
        _write_atomic(dst, payload)
        result.files += 1
        result.input_size += len(data)
        result.output_size += len(payload)
        if result.version is None:
            info = crypto.inspect(payload)
            result.version, result.recipients = info.version, info.recipients

    if is_zip:
        with zipfile.ZipFile(src_abs) as zf:
            for entry in zf.infolist():
                if entry.filename.endswith("/"):
                    continue
                safe = _safe_member_path(entry.filename)
                if safe is None:
                    result.skipped.append((entry.filename, "unsafe path"))
                    continue
                try:
                    if entry.file_size > max_size:
                        raise TMSGSizeError(f"{entry.file_size} bytes exceeds max_size")
                    _one(safe.as_posix(), zf.read(entry))
                except Exception as exc:
                    result.errors.append((entry.filename, str(exc)))
    else:
        for root, dirs, files in os.walk(src_abs):
            dirs.sort()
            for name in sorted(files):
                full = Path(root) / name
                rel = full.relative_to(src_abs).as_posix()
                if full.is_symlink() or not full.is_file():
                    result.skipped.append((rel, "not a regular file (symlink or special file)"))
                    continue
                try:
                    _one(rel, _read_limited(full, max_size))
                except Exception as exc:
                    result.errors.append((rel, str(exc)))
    return result


def _safe_member_path(name: str) -> Optional[PurePosixPath]:
    """
    Return a relative, normalised path for an archive member, or None if it could escape
    the extraction folder (absolute, drive letter, '..', NUL, empty).
    """
    if not name or "\x00" in name:
        return None
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or (len(normalised) > 1 and normalised[1] == ":"):
        return None
    parts = [p for p in normalised.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return PurePosixPath(*parts)


def _extract_archive(
    zip_bytes: bytes,
    out_dir: Path,
    result: FolderResult,
    max_extract_size: int,
    max_files: int,
) -> None:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        entries = [e for e in zf.infolist() if not e.filename.endswith("/")]
        if len(entries) > max_files:
            raise TMSGSizeError(f"archive has {len(entries)} files; the limit is {max_files}",
                                size=len(entries), limit=max_files)
        declared = sum(e.file_size for e in entries)
        if declared > max_extract_size:
            raise TMSGSizeError(
                f"archive would extract to {declared} bytes; the limit is {max_extract_size}",
                size=declared, limit=max_extract_size)

        root = out_dir.resolve()
        written = 0
        for entry in entries:
            safe = _safe_member_path(entry.filename)
            file_type = stat.S_IFMT(entry.external_attr >> 16)    # 0 = no type recorded
            if safe is None:
                result.skipped.append((entry.filename, "unsafe path"))
                continue
            if file_type not in (0, stat.S_IFREG):
                result.skipped.append((entry.filename, "link or special file"))
                continue
            target = (root / safe).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                result.skipped.append((entry.filename, "unsafe path"))
                continue
            try:
                with zf.open(entry) as src:
                    data = src.read(max_extract_size - written + 1)
                written += len(data)
                if written > max_extract_size:
                    raise TMSGSizeError("extracted data exceeds the size limit",
                                        size=written, limit=max_extract_size)
                _write_atomic(target, data)
                result.files += 1
                result.output_size += len(data)
            except TMSGSizeError:
                raise
            except Exception as exc:
                result.errors.append((entry.filename, str(exc)))


def decrypt_folder(
    path: PathLike,
    private_keys: Union[PrivateKeyLike, Iterable[PrivateKeyLike]],
    output: Optional[PathLike] = None,
    *,
    overwrite: bool = False,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
    max_extract_size: int = DEFAULT_MAX_EXTRACT_SIZE,
    max_files: int = DEFAULT_MAX_ARCHIVE_FILES,
) -> FolderResult:
    """
    Decrypt a ``.zip.enc`` archive or a folder of ``.enc`` files.

    * ``<name>.zip.enc`` (a file)  -> decrypted, checked to be a ZIP, extracted into ``<name>_dec/``
    * a folder                     -> every ``*.enc`` inside is decrypted into ``<folder>_dec/``,
                                      same structure. A file that fails does not stop the others.

    Hostile archives are handled safely: unsafe member paths and links are skipped
    (``result.skipped``), and ``max_extract_size`` / ``max_files`` bound what is written.
    """
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(f"path not found: {src}")
    src_abs = src.resolve()

    # ── .zip.enc blob ───────────────────────────────────────────────────────
    if src_abs.is_file():
        if not src_abs.name.endswith(ENC_SUFFIX):
            raise TMSGFormatError("file does not have a .enc extension")
        payload = _read_limited(src_abs, max_size)
        info = crypto.inspect(payload)
        zip_bytes = crypto.decrypt(payload, private_keys)
        if not zipfile.is_zipfile(io.BytesIO(zip_bytes)):
            raise TMSGFormatError(
                "decryption succeeded but the result is not a ZIP archive "
                "(use decrypt_file() for a single encrypted file)"
            )
        name = src_abs.name
        for suffix in (ARCHIVE_SUFFIX, ENC_SUFFIX):
            if name.endswith(suffix):
                name = name[:-len(suffix)]
                break
        out_dir = _choose_output(src_abs.parent / f"{name}_dec", output, overwrite)
        result = FolderResult(out_dir, "extract", input_size=len(payload),
                              version=info.version, recipients=info.recipients)
        out_dir.mkdir(parents=True, exist_ok=True)
        _extract_archive(zip_bytes, out_dir, result, max_extract_size, max_files)
        return result

    # ── folder of .enc files ────────────────────────────────────────────────
    out_root = _choose_output(src_abs.parent / f"{src_abs.name}_dec", output, overwrite)
    result = FolderResult(out_root, "decrypt-files")
    enc_files = []
    for root, dirs, files in os.walk(src_abs):
        dirs.sort()
        for name in sorted(files):
            if name.endswith(ENC_SUFFIX):
                enc_files.append(Path(root) / name)
    if not enc_files:
        raise TMSGFormatError("no .enc files found in the folder")
    if len(enc_files) > max_files:
        raise TMSGSizeError(f"{len(enc_files)} files; the limit is {max_files}",
                            size=len(enc_files), limit=max_files)

    written = 0
    for full in enc_files:
        rel = full.relative_to(src_abs).as_posix()
        try:
            if full.is_symlink():
                result.skipped.append((rel, "symlink"))
                continue
            payload = _read_limited(full, max_size)
            info = crypto.inspect(payload)
            plaintext = crypto.decrypt(payload, private_keys)
            written += len(plaintext)
            if written > max_extract_size:
                raise TMSGSizeError("decrypted data exceeds the size limit",
                                    size=written, limit=max_extract_size)
            dst = out_root / rel[:-len(ENC_SUFFIX)]
            _write_atomic(dst, plaintext)
            result.files += 1
            result.input_size += len(payload)
            result.output_size += len(plaintext)
            if result.version is None:
                result.version, result.recipients = info.version, info.recipients
        except TMSGSizeError as exc:
            if exc.limit == max_extract_size:
                raise
            result.errors.append((rel, str(exc)))
        except Exception as exc:
            result.errors.append((rel, str(exc)))
    return result

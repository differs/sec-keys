#!/usr/bin/env python3
"""
EVM Key Manager — Generate, encrypt, and manage Ethereum private keys.

Dependencies:
    pip install cryptography pycryptodome

Basic usage:
    # Generate 5 new keys  →  saved as 20260623_a1f2.csv.enc
    python evm_key_manager.py generate 5

    # Use a specific file instead of auto-naming
    python evm_key_manager.py generate 3 -f my_wallet.csv.enc

    # List all stored keys in a given file
    python evm_key_manager.py list -f 20260623_a1f2.csv.enc

    # Export keys to a plaintext CSV (careful!)
    python evm_key_manager.py export -f 20260623_a1f2.csv.enc --decrypt -o keys_plain.csv

    # Export keys re-encrypted with a different password
    python evm_key_manager.py export -f 20260623_a1f2.csv.enc -o keys_backup.csv.enc
"""

import argparse
import base64
import csv
import datetime
import getpass
import glob
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

try:
    from Crypto.Hash import keccak
except ImportError:
    print(
        "Error: pycryptodome is required.  Install with:  pip install pycryptodome",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ARGON2_SALT_LEN = 16          # 128-bit random salt
ARGON2_ITERATIONS = 3         # time cost
ARGON2_LANES = 1              # parallelism (single-threaded)
ARGON2_MEM_COST = 64 * 1024   # 64 MiB (in KiB)
AES_NONCE_LEN = 12            # 96-bit nonce for AES-256-GCM
AES_KEY_LEN = 32              # 256-bit AES key

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# ---------------------------------------------------------------------------
# File naming helpers
# ---------------------------------------------------------------------------

def _date_stamped_path() -> str:
    """Return a path like ``20260623_a1f2.csv.enc``.

    The 4-char suffix is random hex, so multiple generations on the same day
    will not collide.
    """
    today = datetime.date.today().strftime("%Y%m%d")
    suffix = secrets.token_hex(2)  # 4 hex chars
    return f"{today}_{suffix}.csv.enc"


def _resolve_generate_path(cli_path: str | None) -> str:
    """Return the path to use for ``generate``.

    If the caller passed ``-f`` we respect it; otherwise auto-name.
    """
    return cli_path if cli_path is not None else _date_stamped_path()


def _resolve_read_path(cli_path: str | None) -> str:
    """Return the path to use for ``list`` / ``export``.

    If the caller passed ``-f`` we use it.  Otherwise list available
    ``.csv.enc`` files and either pick the most recent one or show an
    error.
    """
    if cli_path is not None:
        return cli_path

    enc_files = sorted(glob.glob("*.[Cc][Ss][Vv].[Ee][Nn][Cc]"))
    if not enc_files:
        print(
            "No encrypted CSV files found in the current directory.\n"
            "  Specify one with:  -f <filename>",
            file=sys.stderr,
        )
        sys.exit(1)
    if len(enc_files) == 1:
        return enc_files[0]

    print(
        "Multiple encrypted CSV files found.  Please specify one:\n"
        + "\n".join(f"    -f {f}" for f in enc_files),
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Key & address helpers
# ---------------------------------------------------------------------------

def generate_private_key() -> bytes:
    """Return a random 32-byte private key that is a valid secp256k1 scalar."""
    while True:
        key_bytes = secrets.token_bytes(32)
        key_int = int.from_bytes(key_bytes, "big")
        if 0 < key_int < SECP256K1_ORDER:
            return key_bytes


def private_key_to_address(private_key_bytes: bytes) -> str:
    """Derive the hex 0x-prefixed Ethereum address from a private key."""
    key_int = int.from_bytes(private_key_bytes, "big")
    private_key = ec.derive_private_key(key_int, ec.SECP256K1())
    public_key = private_key.public_key()

    # Uncompressed point: 0x04 | X (32 bytes) | Y (32 bytes)
    from cryptography.hazmat.primitives import serialization
    pub_bytes = public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    # Strip the 0x04 prefix before hashing
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(pub_bytes[1:])
    address_bytes = keccak_hash.digest()[-20:]

    return "0x" + address_bytes.hex()


def private_key_to_hex(private_key_bytes: bytes) -> str:
    """Return the 0x-prefixed hex string of a private key."""
    return "0x" + private_key_bytes.hex()


# ---------------------------------------------------------------------------
# Encryption / decryption  (Argon2id + AES-256-GCM)
# ---------------------------------------------------------------------------

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES-GCM key from *password* using Argon2id."""
    kdf = Argon2id(
        salt,
        AES_KEY_LEN,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
        ARGON2_MEM_COST,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(plaintext: str, password: str) -> tuple[bytes, bytes, bytes]:
    """Encrypt *plaintext* with *password*.

    Returns ``(salt, nonce, ciphertext)``.
    ``ciphertext`` already includes the GCM authentication tag.
    """
    salt = os.urandom(ARGON2_SALT_LEN)
    nonce = os.urandom(AES_NONCE_LEN)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return salt, nonce, ciphertext


def decrypt_data(
    ciphertext: bytes, password: str, salt: bytes, nonce: bytes
) -> str:
    """Decrypt AES-GCM ciphertext previously produced by :func:`encrypt_data`."""
    key = _derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")


# ---------------------------------------------------------------------------
# Encrypted CSV I/O  (container format v2)
# ---------------------------------------------------------------------------

_CONTAINER_VERSION = 2


def save_encrypted_csv(path: str, keys: list[dict[str, str]], password: str) -> None:
    """Write *keys* to *path* as an encrypted CSV (Argon2id + AES-256-GCM).

    Each dict in *keys* must have ``"private_key"`` and ``"address"`` keys.
    """
    csv_content = "private_key,address\n"
    for k in keys:
        csv_content += f"{k['private_key']},{k['address']}\n"

    salt, nonce, ciphertext = encrypt_data(csv_content, password)

    container = {
        "version": _CONTAINER_VERSION,
        "kdf": {
            "type": "argon2id",
            "salt": base64.b64encode(salt).decode(),
            "iterations": ARGON2_ITERATIONS,
            "lanes": ARGON2_LANES,
            "memory_cost_kib": ARGON2_MEM_COST,
        },
        "nonce": base64.b64encode(nonce).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }

    with open(path, "w") as f:
        json.dump(container, f, separators=(",", ":"))

    os.chmod(path, 0o600)


def load_encrypted_csv(path: str, password: str) -> list[dict[str, str]]:
    """Load and decrypt a CSV saved with :func:`save_encrypted_csv`.

    Only container format v2 (Argon2id + AES-256-GCM) is supported.
    Returns a list of dicts with ``"private_key"`` and ``"address"`` keys.
    """
    with open(path) as f:
        container = json.load(f)

    kdf_info = container["kdf"]
    salt = base64.b64decode(kdf_info["salt"])
    nonce = base64.b64decode(container["nonce"])
    ciphertext = base64.b64decode(container["data"])

    csv_content = decrypt_data(ciphertext, password, salt, nonce)

    reader = csv.DictReader(csv_content.splitlines())
    return [
        {"private_key": row["private_key"], "address": row["address"]}
        for row in reader
    ]


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_generate(count: int, path: str | None) -> None:
    """Generate *count* new keys and save to an encrypted CSV.

    *path* is the CLI ``-f`` value (or ``None`` if omitted → auto-name).
    """
    path = _resolve_generate_path(path)
    existing_keys: list[dict[str, str]] = []
    password: str | None = None

    if os.path.exists(path):
        print(f"  File {path!r} exists — will append new keys to it.")
        password = getpass.getpass("  Password for existing store: ")
        try:
            existing_keys = load_encrypted_csv(path, password)
        except Exception as exc:
            print(f"  Failed to decrypt existing file: {exc}", file=sys.stderr)
            sys.exit(1)
        print(f"  Loaded {len(existing_keys)} existing key(s).")
    else:
        password = getpass.getpass("  Password for NEW key store: ")
        confirm = getpass.getpass("  Confirm password: ")
        if password != confirm:
            print("  Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    new_keys: list[dict[str, str]] = []
    for _ in range(count):
        priv_bytes = generate_private_key()
        new_keys.append({
            "private_key": private_key_to_hex(priv_bytes),
            "address": private_key_to_address(priv_bytes),
        })

    all_keys = existing_keys + new_keys
    save_encrypted_csv(path, all_keys, password)

    print(f"\n✔ Generated {count} new key(s).  Total in store: {len(all_keys)}")
    print(f"   Store: {path}")
    print()
    _print_table(new_keys, header="Newly generated keys")
    print()


def cmd_list(path: str | None) -> None:
    """Display every stored key-pair."""
    path = _resolve_read_path(path)

    password = getpass.getpass("Password: ")
    try:
        keys = load_encrypted_csv(path, password)
    except Exception as exc:
        print(f"Failed to decrypt: {exc}", file=sys.stderr)
        sys.exit(1)

    print()
    _print_table(keys, header=f"Stored keys ({len(keys)} total)  [{path}]")
    print()


def cmd_export(path: str | None, output: str, decrypt: bool) -> None:
    """Export keys — either as plaintext CSV or re-encrypted."""
    path = _resolve_read_path(path)

    password = getpass.getpass("Password for source store: ")
    try:
        keys = load_encrypted_csv(path, password)
    except Exception as exc:
        print(f"Failed to decrypt: {exc}", file=sys.stderr)
        sys.exit(1)

    if decrypt:
        with open(output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["private_key", "address"])
            writer.writerows((k["private_key"], k["address"]) for k in keys)
        os.chmod(output, 0o600)
        print(f"Exported {len(keys)} key(s) to {output!r}  [PLAINTEXT — handle with care]")
    else:
        new_password = getpass.getpass("Password for exported store:  ")
        confirm = getpass.getpass("Confirm password: ")
        if new_password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
        save_encrypted_csv(output, keys, new_password)
        print(f"Exported {len(keys)} key(s) to {output!r}  [encrypted]")


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _print_table(keys: list[dict[str, str]], header: str = "") -> None:
    """Print a simple aligned table of private keys and addresses."""
    if header:
        print(f"  {header}")
        print()

    if not keys:
        print("  (empty)")
        return

    # Column widths
    idx_w = max(len(str(len(keys))) + 1, 3)
    sep = "─" * (idx_w + 2 + 68 + 2 + 44)

    print(f"  {'#':>{idx_w}}  {'PRIVATE KEY':<68}  ADDRESS")
    print(f"  {sep}")
    for i, k in enumerate(keys, 1):
        print(f"  {i:>{idx_w}}  {k['private_key']:<68}  {k['address']}")
    print(f"  {sep}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _add_file_arg(parser: argparse.ArgumentParser) -> None:
    """Attach the ``-f/--file`` argument to *parser*."""
    parser.add_argument(
        "-f", "--file",
        default=None,
        help=(
            "Encrypted CSV file path.\n"
            "  generate: auto-named as YYYYMMDD_XXXX.csv.enc when omitted\n"
            "  list/export: auto-picks the most recent .csv.enc when omitted"
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="evm_key_manager.py",
        description="EVM Key Manager — Generate, encrypt, and manage Ethereum private keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s generate 5\n"
            "  %(prog)s generate 3 -f my_keys.csv.enc\n"
            "  %(prog)s list -f 20260623_a1f2.csv.enc\n"
            "  %(prog)s export -f 20260623_a1f2.csv.enc --decrypt -o plain_keys.csv\n"
        ),
    )

    _add_file_arg(parser)

    sub = parser.add_subparsers(dest="command", required=False)

    # --- generate ---
    gen = sub.add_parser("generate", help="Generate new private key(s)")
    _add_file_arg(gen)
    gen.add_argument(
        "count",
        nargs="?",
        type=int,
        default=1,
        help="Number of keys to generate (default: 1)",
    )

    # --- list ---
    list_ = sub.add_parser("list", help="List all stored keys with private key and address")
    _add_file_arg(list_)

    # --- export ---
    exp = sub.add_parser("export", help="Export keys (plaintext or re-encrypted)")
    _add_file_arg(exp)
    exp.add_argument("-o", "--output", default="exported_keys.csv", help="Output path")
    exp.add_argument(
        "-d", "--decrypt",
        action="store_true",
        help="Export as plaintext CSV (default: re-encrypted)",
    )

    args = parser.parse_args()

    try:
        if args.command == "generate":
            if args.count < 1:
                print("Count must be ≥ 1.", file=sys.stderr)
                sys.exit(1)
            cmd_generate(args.count, args.file)
        elif args.command == "list":
            cmd_list(args.file)
        elif args.command == "export":
            cmd_export(args.file, args.output, args.decrypt)
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()

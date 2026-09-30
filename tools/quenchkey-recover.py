#!/usr/bin/env python3
# Copyright 2026 Quenchkey contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Open and audit a Quenchkey vault without Quenchkey.

This file is deliberately standalone. It imports nothing from the ``quenchkey``
package and needs no Qt, no py7zr and no project checkout — only
``cryptography`` and ``argon2-cffi``, both on PyPI and in most distributions:

    pip install cryptography argon2-cffi
    pip install shamir-mnemonic     # only for the recovery-share commands

It exists to make one claim checkable rather than asked for on trust: the
application is a convenience, not a dependency. The vault, the locked files and
the certificates are documented formats protected by standard primitives, and
anything that can run Python can read them given the passphrase. If this
project disappears tomorrow, your data does not.

It re-implements every format from scratch, in a few hundred lines, rather than
importing them. That is the point: code shared with the application would only
prove the application agrees with itself. It also means the two implementations
check each other — the test suite runs this script against vaults the
application wrote, so an ambiguity in the format shows up as a failure.

Commands
--------

    list       VAULT                     every entry, with its rules
    extract    VAULT ENTRY_ID  -o DIR    decrypt and unpack one entry
    decrypt    VAULT BLOB      -o FILE   decrypt a .qkey to its archive
    audit      VAULT                     verify the event chain, show the anchor
    certificates VAULT                   list and export destruction certificates
    verify     CERT [--vault VAULT] [--file BLOB]
                                         check a certificate signature
    audit-record RECORD [--public-key HEX]
                                         read an auditor's record: entries,
                                         rules, destructions and the event
                                         chain, with no keys in it and no
                                         vault needed

Credentials: --keyfile for a keyfile vault, --shares to open one with recovery
shares instead of the passphrase.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from typing import Optional

try:
    from argon2.low_level import Type as Argon2Type, hash_secret_raw
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as exc:  # pragma: no cover - environment problem, not logic
    sys.exit(f"missing dependency: {exc}\n\n"
             "    pip install cryptography argon2-cffi")

# ---------------------------------------------------------------------------
# format constants, transcribed from the documented layouts
# ---------------------------------------------------------------------------

VAULT_MAGIC = b"QKEYVALT"
HEADER_FIXED_LEN = 40
LEGACY_HEADER_LEN = 52

BLOB_MAGIC = b"QKEYLOCK"
BLOB_HEADER_LEN = 44

#: Header flag: this file carries its own key, wrapped by a passphrase of its
#: own. There is no vault behind it, and no deadline — the key is inside every
#: copy, so there is nothing anywhere that could be destroyed to revoke it.
FLAG_SELF_CONTAINED = 0x0001


KEY_SIZE = 32
TAG_SIZE = 16

SHARE_STRUCT = ">BBH16sIII12s"
SHARE_PREFIX_LEN = struct.calcsize(SHARE_STRUCT)
SHARE_BLOCK_LEN = SHARE_PREFIX_LEN + KEY_SIZE + TAG_SIZE
FLAG_KEYFILE_REQUIRED = 0x01
FLAG_FIDO2_REQUIRED = 0x02
KEYFILE_DOMAIN = b"quenchkey/keyfile/v1"
KEYFILE_READ_BYTES = 1024 * 1024
ARCHIVE_PASSWORD_INFO = b"quenchkey/archive-password/v1"

EVENT_DOMAIN = b"quenchkey/event/v1"
CHAIN_GENESIS = "0" * 64
CERTIFICATE_DOMAIN = b"quenchkey/certificate/v1"
VAULT_ID_DOMAIN = b"quenchkey/vault-id/v1"


def aead(cipher_id: int, key: bytes):
    if cipher_id == 1:
        return ChaCha20Poly1305(key)
    if cipher_id == 2:
        return AESGCM(key)
    raise SystemExit(f"unknown cipher id {cipher_id}")


def canonical(payload: dict, drop=("hash",)) -> bytes:
    """Deterministic JSON, matching the application's canonical form."""
    trimmed = {k: v for k, v in payload.items() if k not in drop}
    return json.dumps(trimmed, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# the vault
# ---------------------------------------------------------------------------

def parse_header(raw: bytes) -> dict:
    if len(raw) < HEADER_FIXED_LEN or raw[:8] != VAULT_MAGIC:
        raise SystemExit("this is not a Quenchkey vault")
    version, kdf_id, cipher_id, flags, salt, t_cost, memory, parallel = struct.unpack(
        ">BBBB16sIII", raw[8:HEADER_FIXED_LEN])
    if version not in (1, 2):
        raise SystemExit(f"vault format version {version}; this tool reads 1 and 2")
    if kdf_id != 1:
        raise SystemExit(f"unknown KDF id {kdf_id}")

    if version == 1:
        aad = raw[:HEADER_FIXED_LEN]
        nonce = raw[HEADER_FIXED_LEN:LEGACY_HEADER_LEN]
        body_offset = LEGACY_HEADER_LEN
        factor_params: dict = {}
    else:
        (block_len,) = struct.unpack(">H", raw[HEADER_FIXED_LEN:HEADER_FIXED_LEN + 2])
        start = HEADER_FIXED_LEN + 2
        block = raw[start:start + block_len]
        aad = raw[:start + block_len]
        nonce = raw[start + block_len:start + block_len + 12]
        body_offset = start + block_len + 12
        factor_params = json.loads(block.decode("utf-8")) if block else {}

    return {"version": version, "cipher_id": cipher_id, "flags": flags,
            "salt": salt, "time_cost": t_cost, "memory": memory,
            "parallelism": parallel, "aad": aad, "nonce": nonce,
            "body_offset": body_offset, "factor_params": factor_params}


def derive_master(header: dict, passphrase: str, keyfile: Optional[str]) -> bytes:
    secret = passphrase.encode("utf-8")
    if header["flags"] & FLAG_FIDO2_REQUIRED:
        raise SystemExit(
            "this vault is protected by a hardware security key. This recovery "
            "tool cannot drive one — use the application, or open the vault "
            "with recovery shares (--shares) if you have a quorum.")
    if header["flags"] & FLAG_KEYFILE_REQUIRED:
        if not keyfile:
            raise SystemExit("this vault requires a keyfile: pass --keyfile")
        digest = hashlib.sha256()
        digest.update(KEYFILE_DOMAIN)
        with open(keyfile, "rb") as fh:
            digest.update(fh.read(KEYFILE_READ_BYTES))
        secret += b"\x00" + digest.digest()

    print(f"deriving the key: Argon2id, {header['memory'] // 1024} MiB, "
          f"{header['time_cost']} pass"
          f"{'es' if header['time_cost'] != 1 else ''}, "
          f"parallelism {header['parallelism']}...", file=sys.stderr)
    return hash_secret_raw(secret=secret, salt=header["salt"],
                           time_cost=header["time_cost"],
                           memory_cost=header["memory"],
                           parallelism=header["parallelism"],
                           hash_len=KEY_SIZE, type=Argon2Type.ID)


def master_from_shares(share_text: Optional[str]) -> bytes:
    """Reconstruct a master key from SLIP-39 recovery shares."""
    try:
        import shamir_mnemonic
    except ImportError:
        raise SystemExit("recovery shares need the shamir-mnemonic package:\n\n"
                         "    pip install shamir-mnemonic")

    shares: list[str] = []
    if share_text:
        source = open(share_text).read() if os.path.exists(share_text) else share_text
        shares = [line.strip() for line in source.splitlines() if line.strip()
                  and not line.strip().startswith("#")]
    if not shares:
        print("Enter recovery shares, one per line. Blank line when done.",
              file=sys.stderr)
        while True:
            line = input().strip()
            if not line:
                break
            shares.append(line)
    if not shares:
        raise SystemExit("no shares given")

    threshold = None
    try:
        parsed = shamir_mnemonic.share.Share.from_mnemonic(shares[0].lower())
        threshold = parsed.member_threshold
    except Exception:  # noqa: BLE001
        pass
    usable = shares[:threshold] if threshold else shares

    try:
        secret = shamir_mnemonic.combine_mnemonics([s.lower() for s in usable],
                                                   passphrase=b"")
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"the shares could not be combined: {exc}")
    if len(secret) != KEY_SIZE:
        raise SystemExit("those shares do not belong to a Quenchkey vault")
    print(f"reconstructed the master key from {len(usable)} shares",
          file=sys.stderr)
    return secret


def read_vault(path: str, passphrase: Optional[str], keyfile: Optional[str],
               shares: Optional[str] = None, use_shares: bool = False) -> dict:
    with open(path, "rb") as fh:
        raw = fh.read()
    header = parse_header(raw)

    if use_shares:
        master = master_from_shares(shares)
    else:
        if passphrase is None:
            passphrase = getpass.getpass("Vault passphrase: ")
        master = derive_master(header, passphrase, keyfile)

    try:
        payload = aead(header["cipher_id"], master).decrypt(
            header["nonce"], raw[header["body_offset"]:], header["aad"])
    except InvalidTag:
        raise SystemExit(
            "the vault did not open: wrong passphrase, wrong or missing "
            "keyfile, wrong recovery shares, or the file has been altered")

    vault = parse_payload(payload)
    vault["header"] = header
    return vault


def parse_payload(buf: bytes) -> dict:
    position = 0

    def take(count: int) -> bytes:
        nonlocal position
        if position + count > len(buf):
            raise SystemExit("the vault payload is truncated")
        chunk = buf[position:position + count]
        position += count
        return chunk

    (payload_version,) = struct.unpack(">B", take(1))

    if payload_version == 1:
        created, last_seen, entry_count = struct.unpack(">ddI", take(20))
        entries = take_entries(take, entry_count)
        events = []
        (event_count,) = struct.unpack(">I", take(4))
        for _ in range(event_count):
            (blob_len,) = struct.unpack(">I", take(4))
            events.append(json.loads(take(blob_len).decode("utf-8")))
        extras = {"events": events}
        signing_public = None
    elif payload_version == 2:
        created, last_seen = struct.unpack(">dd", take(16))
        seed = take(32)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        signing_public = Ed25519PrivateKey.from_private_bytes(seed).public_key(
        ).public_bytes(Encoding.Raw, PublicFormat.Raw)
        (entry_count,) = struct.unpack(">I", take(4))
        entries = take_entries(take, entry_count)
        (extras_len,) = struct.unpack(">I", take(4))
        extras = json.loads(take(extras_len).decode("utf-8")) if extras_len else {}
    else:
        raise SystemExit(f"unknown payload version {payload_version}")

    return {"payload_version": payload_version, "created": created,
            "last_seen": last_seen, "entries": entries,
            "events": extras.get("events", []),
            "certificates": extras.get("certificates", []),
            "custodian": extras.get("custodian", {}),
            "chain_head": extras.get("chain_head", CHAIN_GENESIS),
            "chain_origin": extras.get("chain_origin"),
            "events_truncated": extras.get("events_truncated", False),
            "public_key": signing_public}


def take_entries(take, count: int) -> list:
    entries = []
    for _ in range(count):
        (meta_len,) = struct.unpack(">I", take(4))
        meta = json.loads(take(meta_len).decode("utf-8"))
        meta["key"] = take(KEY_SIZE)
        entries.append(meta)
    return entries


# ---------------------------------------------------------------------------
# the event chain
# ---------------------------------------------------------------------------

def event_hash(event: dict) -> str:
    return hashlib.sha256(EVENT_DOMAIN + canonical(event)).hexdigest()


def verify_chain(events: list, expected_head: Optional[str]) -> tuple[bool, str]:
    previous = CHAIN_GENESIS
    for index, event in enumerate(events):
        if event.get("seq") != index:
            return False, f"event {index}: sequence number is {event.get('seq')!r}"
        if event.get("prev") != previous:
            return False, f"event {index}: does not follow the one before it"
        recomputed = event_hash(event)
        if event.get("hash") != recomputed:
            return False, f"event {index}: contents do not match its own hash"
        previous = recomputed
    if expected_head and previous != expected_head:
        return False, "the recorded head does not match the events (tail removed?)"
    return True, f"{len(events)} events, chain intact"


def fingerprint(head: str) -> str:
    trimmed = head[:16]
    return "-".join(trimmed[i:i + 4] for i in range(0, 16, 4)).upper()


# ---------------------------------------------------------------------------
# certificates
# ---------------------------------------------------------------------------

def verify_certificate(document: dict, expected_public: Optional[bytes] = None) -> tuple:
    try:
        body = document["certificate"]
        public = bytes.fromhex(document["public_key"])
        signature = bytes.fromhex(document["signature"])
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"malformed certificate: {exc}"

    if body.get("format") != "quenchkey-destruction-certificate":
        return False, "not a Quenchkey destruction certificate"
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, CERTIFICATE_DOMAIN + canonical(body))
    except (InvalidSignature, ValueError):
        return False, ("the contents do not match the signature: altered, or "
                       "not signed by the key it names")

    expected_id = hashlib.sha256(VAULT_ID_DOMAIN + public).hexdigest()[:32]
    if body.get("vault_id") != expected_id:
        return False, "the vault id does not match the signing public key"
    if expected_public is not None and public != expected_public:
        return False, "signed by a different vault than the one given"
    return True, "signature valid"


def file_digest(path: str) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# the locked file
# ---------------------------------------------------------------------------

def decrypt_blob(blob_path: str, key: bytes, destination: str) -> str:
    with open(blob_path, "rb") as source:
        header = source.read(BLOB_HEADER_LEN)
        if len(header) < BLOB_HEADER_LEN or header[:8] != BLOB_MAGIC:
            raise SystemExit(f"{blob_path} is not a Quenchkey locked file")
        (version, cipher_id, flags, entry_id, prefix, chunk_size,
         plaintext_len) = struct.unpack(">BBH16s4sIQ", header[8:BLOB_HEADER_LEN])
        if version != 1:
            raise SystemExit(f"locked-file version {version}; this tool reads 1")

        # A self-contained file keeps its wrapped key straight after the fixed
        # header, and every chunk is authenticated against both together.
        if flags & FLAG_SELF_CONTAINED:
            header += source.read(SHARE_BLOCK_LEN)
            if len(header) != BLOB_HEADER_LEN + SHARE_BLOCK_LEN:
                raise SystemExit("the locked file is truncated")

        cipher = aead(cipher_id, key)
        remaining = plaintext_len
        index = 0
        with open(destination, "wb") as out:
            while True:
                final = remaining <= chunk_size
                want = (remaining + TAG_SIZE) if final else (chunk_size + TAG_SIZE)
                sealed = source.read(want)
                if len(sealed) != want:
                    raise SystemExit("the locked file is truncated")
                nonce = prefix + struct.pack(">Q", index)
                associated = header + struct.pack(">Q?", index, final)
                try:
                    plain = cipher.decrypt(nonce, sealed, associated)
                except InvalidTag:
                    raise SystemExit(
                        f"chunk {index} failed authentication: wrong key, or "
                        "the file has been altered")
                out.write(plain)
                remaining -= len(plain)
                index += 1
                if final:
                    break
    return destination


def read_share_block(blob_path: str) -> dict:
    """The key block of a self-contained file, without deriving anything."""
    with open(blob_path, "rb") as fh:
        header = fh.read(BLOB_HEADER_LEN)
        if len(header) < BLOB_HEADER_LEN or header[:8] != BLOB_MAGIC:
            raise SystemExit(f"{blob_path} is not a Quenchkey locked file")
        (version, cipher_id, flags, entry_id, _prefix, chunk_size,
         plaintext_len) = struct.unpack(">BBH16s4sIQ", header[8:BLOB_HEADER_LEN])
        if version != 1:
            raise SystemExit(f"locked-file version {version}; this tool reads 1")
        if not (flags & FLAG_SELF_CONTAINED):
            raise SystemExit(
                f"{blob_path} keeps its key in a vault, not in itself. Use "
                f"`extract` with the vault that holds it.")
        block = fh.read(SHARE_BLOCK_LEN)
    if len(block) != SHARE_BLOCK_LEN:
        raise SystemExit("the key block in this file is truncated")

    (kdf_id, block_cipher, _reserved, salt, time_cost, memory_kib,
     parallelism, nonce) = struct.unpack(SHARE_STRUCT, block[:SHARE_PREFIX_LEN])
    if kdf_id != 1:
        raise SystemExit(f"unknown key derivation {kdf_id} in this file")
    if not (1 <= time_cost <= 64) or not (8 <= memory_kib <= 4 * 1024 * 1024) \
            or not (1 <= parallelism <= 64):
        raise SystemExit("implausible key derivation cost in this file")

    # The wrap is authenticated against the fixed header with its nonce prefix
    # zeroed, which is how the application writes it: the prefix is chosen by
    # the encryption pass afterwards, and is covered by every chunk instead.
    bare = BLOB_MAGIC + struct.pack(">BBH16s4sIQ", version, cipher_id, flags,
                                    entry_id, b"\x00" * 4, chunk_size,
                                    plaintext_len)
    return {
        "cipher_id": cipher_id, "block_cipher": block_cipher, "salt": salt,
        "time_cost": time_cost, "memory": memory_kib, "parallelism": parallelism,
        "nonce": nonce, "wrapped": block[SHARE_PREFIX_LEN:],
        "aad": bare + block[:SHARE_PREFIX_LEN], "names_hint": plaintext_len,
    }


def unwrap_share_key(block: dict, passphrase: str) -> bytes:
    print(f"deriving the key: Argon2id, {block['memory'] // 1024} MiB, "
          f"{block['time_cost']} pass"
          f"{'es' if block['time_cost'] != 1 else ''}, "
          f"parallelism {block['parallelism']}...", file=sys.stderr)
    kek = hash_secret_raw(secret=passphrase.encode("utf-8"), salt=block["salt"],
                          time_cost=block["time_cost"],
                          memory_cost=block["memory"],
                          parallelism=block["parallelism"],
                          hash_len=KEY_SIZE, type=Argon2Type.ID)
    try:
        return aead(block["block_cipher"], kek).decrypt(
            block["nonce"], block["wrapped"], block["aad"])
    except InvalidTag:
        raise SystemExit(
            "wrong passphrase, or this file has been altered. There is no way "
            "to tell which from here, and no attempt is made to guess.")


def archive_password(key: bytes) -> str:
    import base64
    material = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=ARCHIVE_PASSWORD_INFO).derive(key)
    return base64.urlsafe_b64encode(material).decode("ascii").rstrip("=")


def try_unpack(archive_path: str, key: bytes, destination: str) -> bool:
    password = archive_password(key)
    try:
        import py7zr

        with py7zr.SevenZipFile(archive_path, "r", password=password) as sz:
            sz.extractall(path=destination)
        return True
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001
        print(f"py7zr could not unpack it: {exc}", file=sys.stderr)

    for binary in ("7z", "7za", "7zz"):
        if shutil.which(binary):
            result = subprocess.run(
                [binary, "x", f"-p{password}", f"-o{destination}", "-y", archive_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if result.returncode == 0:
                return True
            print(f"{binary} failed: {result.stderr.decode(errors='replace')[:200]}",
                  file=sys.stderr)
    return False


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def when(value: Optional[float]) -> str:
    if value is None:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(value))


def describe(entry: dict) -> str:
    destroyed = entry["key"] == bytes(KEY_SIZE) or entry.get("status") == "expired"
    state = "KEY DESTROYED" if destroyed else "key present"

    rules = []
    if entry.get("expires") is not None:
        rules.append(f"deadline {when(entry['expires'])}")
    if entry.get("heartbeat_days") is not None:
        rules.append(f"check in every {entry['heartbeat_days']:g}d")
    if entry.get("max_opens") is not None:
        rules.append(f"{entry.get('open_count', 0)}/{entry['max_opens']} opens")

    lines = [f"{entry['id']}  [{state}]",
             f"    files    : {', '.join(entry.get('names', [])) or '(none recorded)'}",
             f"    locked   : {entry['blob_path']}",
             f"    rules    : {', '.join(rules) if rules else 'none'}"]
    if entry.get("blob_sha256"):
        lines.append(f"    sha256   : {entry['blob_sha256']}")
    if destroyed and entry.get("destruction_reason"):
        lines.append(f"    destroyed: {when(entry.get('expired_at'))} — "
                     f"{entry['destruction_reason']}")
    return "\n".join(lines)


def find_entry(vault: dict, entry_id: str) -> dict:
    matches = [e for e in vault["entries"] if e["id"].startswith(entry_id)]
    if not matches:
        raise SystemExit(f"no entry starting with {entry_id!r}")
    if len(matches) > 1:
        raise SystemExit(f"{entry_id!r} matches {len(matches)} entries; be more specific")
    entry = matches[0]
    if entry["key"] == bytes(KEY_SIZE):
        raise SystemExit(
            f"the key for {entry['id']} was destroyed. The locked file may still "
            "exist and is permanently unreadable — by this tool, by Quenchkey, "
            "and by anything else. That is what expiry means.")
    return entry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quenchkey-recover",
        description="Open and audit a Quenchkey vault without the application.")
    parser.add_argument("--keyfile", help="keyfile, if the vault requires one")
    parser.add_argument("--shares", nargs="?", const="", default=None,
                        metavar="FILE",
                        help="open with recovery shares instead of the "
                             "passphrase; give a file of shares, or omit the "
                             "value to be prompted")
    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("list", help="show every entry in the vault")
    listing.add_argument("vault")

    extract = sub.add_parser("extract", help="decrypt and unpack one entry")
    extract.add_argument("vault")
    extract.add_argument("entry_id", help="full id, or enough of it to be unique")
    extract.add_argument("--output", "-o", default="quenchkey-recovered")

    decrypt = sub.add_parser("decrypt", help="decrypt a .qkey to its archive")
    decrypt.add_argument("vault")
    decrypt.add_argument("blob")
    decrypt.add_argument("--output", "-o", default=None)

    audit = sub.add_parser("audit", help="verify the event chain and show the anchor")
    audit.add_argument("vault")
    audit.add_argument("--expect", help="a chain fingerprint or head you recorded earlier")

    certs = sub.add_parser("certificates", help="list or export destruction certificates")
    certs.add_argument("vault")
    certs.add_argument("--output", "-o", help="directory to write them to")

    record = sub.add_parser(
        "audit-record",
        help="read an auditor's record: no vault, no keys, no application")
    record.add_argument("record", help="the .audit file")
    record.add_argument("--public-key", metavar="HEX",
                        help="the vault's public key, from any certificate it "
                             "has issued, so the signature is checked against "
                             "a key you brought yourself")

    verify = sub.add_parser("verify", help="check a destruction certificate")
    verify.add_argument("certificate")
    verify.add_argument("--vault", help="confirm it came from this vault")
    verify.add_argument("--file", help="confirm a .qkey is the one described")

    share = sub.add_parser(
        "share",
        help="open a self-contained .qkey with its own passphrase (no vault)")
    share.add_argument("file", help="the .qkey file that was shared with you")
    share.add_argument("-o", "--output", default=".",
                       help="where to put the files (default: here)")
    share.add_argument("--describe", action="store_true",
                       help="say what the file is without opening it")
    return parser


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)

    # `verify` is the one command that needs no vault and no secret at all: a
    # counterparty can check a certificate holding nothing but the document.
    if args.command == "verify":
        return command_verify(args)

    # `share` needs no vault either: the key is inside the file, wrapped by a
    # passphrase. That is exactly what makes it shareable, and exactly why it
    # can never expire.
    if args.command == "share":
        return command_share(args)

    # `audit-record` needs no vault either. That is the reason for it:
    # an auditor gets a file and a passphrase, and neither opens a document.
    if args.command == "audit-record":
        return command_audit_record(args)

    passphrase = os.environ.get("QUENCHKEY_PASSPHRASE")
    use_shares = args.shares is not None
    vault = read_vault(args.vault, passphrase, args.keyfile,
                       args.shares or None, use_shares)

    if args.command == "list":
        return command_list(vault, args)
    if args.command == "audit":
        return command_audit(vault, args)
    if args.command == "certificates":
        return command_certificates(vault, args)
    if args.command == "extract":
        return command_extract(vault, args)
    if args.command == "decrypt":
        return command_decrypt(vault, args)
    return 1


def command_audit_record(args) -> int:
    """Read an audit record. Needs its own passphrase and nothing else.

    Re-implemented here rather than imported, like everything else in this
    file. An auditor holding a record and its passphrase can run this and be
    told what the vault claims, whether the chain inside it verifies, and
    whether the signature is the vault's — without the application, without
    the vault, and without ever being able to read a document.
    """
    try:
        with open(args.record) as fh:
            document = json.load(fh)
        header_raw = document["header"].encode("utf-8")
        header = json.loads(document["header"])
        nonce = bytes.fromhex(document["nonce"])
        sealed = bytes.fromhex(document["body"])
    except (OSError, ValueError, KeyError) as exc:
        print(f"could not read that audit record: {exc}", file=sys.stderr)
        return 1

    if header.get("magic") != "QKEYAUDT":
        print("that is not a Quenchkey audit record", file=sys.stderr)
        return 1

    passphrase = (os.environ.get("QUENCHKEY_RECORD_PASSPHRASE")
                  or getpass.getpass("Passphrase for the audit record: "))
    print(f"deriving the key: Argon2id, {int(header['memory_kib']) // 1024} MiB, "
          f"{header['time_cost']} pass"
          f"{'es' if int(header['time_cost']) != 1 else ''}...", file=sys.stderr)
    key = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=bytes.fromhex(header["salt"]),
        time_cost=int(header["time_cost"]),
        memory_cost=int(header["memory_kib"]),
        parallelism=int(header["parallelism"]),
        hash_len=KEY_SIZE, type=Argon2Type.ID)
    try:
        plain = aead(1, key).decrypt(nonce, sealed, header_raw)
    except Exception:  # noqa: BLE001 - one message covers both causes
        print("wrong passphrase for this record, or it has been altered — "
              "there is no way to tell those apart", file=sys.stderr)
        return 1

    if len(plain) <= 64:
        print("this audit record is truncated", file=sys.stderr)
        return 1
    body_raw, signature = plain[:-64], plain[-64:]
    body = json.loads(body_raw.decode("utf-8"))

    supplied = args.public_key
    claimed = header.get("public_key", "")
    checking = (supplied or claimed or "").strip().lower()
    signature_ok = False
    if checking:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            Ed25519PublicKey.from_public_bytes(bytes.fromhex(checking)).verify(
                signature, b"quenchkey/audit-record/v1" + body_raw)
            signature_ok = True
        except Exception:  # noqa: BLE001 - a bad signature is a bad signature
            signature_ok = False

    events = body.get("events", [])
    chain_ok, chain_note = verify_chain(events, body.get("chain_head"))

    print(f"{args.record}")
    print(f"    vault      : {body.get('vault_id', '(none)')}")
    print(f"    written    : {when(body.get('written', 0))}")
    print(f"    anchor     : {body.get('anchor', '(none)')}")
    print(f"    entries    : {len(body.get('entries', []))}")
    print(f"    events     : {len(events)}")
    print(f"    chain      : {'verifies' if chain_ok else chain_note}")
    if not signature_ok:
        verdict = ("does NOT verify — this record cannot be shown to have "
                   "come from that vault")
    elif supplied:
        verdict = "verifies against the key you supplied"
    else:
        verdict = ("verifies against the key inside the record, which shows "
                   "only that the record is self-consistent")
    print(f"    signature  : {verdict}")
    print()

    entries = body.get("entries", [])
    if entries:
        width = max(len(str(e.get("name", ""))) for e in entries)
        for entry in entries:
            state = ("key destroyed" if entry.get("destroyed")
                     else "live")
            gone = (f"  destroyed {when(entry['destroyed_at'])}"
                    if entry.get("destroyed_at") else "")
            rules = []
            if entry.get("expires"):
                rules.append(f"deadline {when(entry['expires'])}")
            if entry.get("max_opens") is not None:
                rules.append(f"{entry.get('open_count', 0)}/"
                             f"{entry['max_opens']} opens")
            if entry.get("heartbeat_days"):
                rules.append(f"check in every {entry['heartbeat_days']:g}d")
            print(f"    {str(entry.get('name', '')):<{width}}  {state:<14}"
                  f"{gone}")
            if rules:
                print(f"    {'':<{width}}  {', '.join(rules)}")
        print()

    certificates = body.get("certificates", [])
    print(f"    {len(certificates)} certificate"
          f"{'s' if len(certificates) != 1 else ''} of destruction recorded")

    if not supplied:
        print()
        print("    The signature was checked against the key printed inside "
              "the record. To check it against a key you brought yourself, "
              "take the public_key from any certificate this vault has issued "
              "and pass --public-key.")
    if not chain_ok or not signature_ok:
        return 4
    return 0


def command_share(args) -> int:
    block = read_share_block(args.file)
    size = os.path.getsize(args.file)

    print(f"{args.file}")
    print("    kind     : self-contained — the key is in this file, wrapped "
          "by a passphrase")
    print("    deadline : none, and none is possible. Whoever has this file "
          "and its")
    print("               passphrase can open it forever; there is no key "
          "held anywhere")
    print("               else that could be destroyed to take that away.")
    print(f"    cipher   : {'ChaCha20-Poly1305' if block['cipher_id'] == 1 else 'AES-256-GCM'}")
    print(f"    key      : Argon2id — {block['memory'] // 1024} MiB, "
          f"{block['time_cost']} pass"
          f"{'es' if block['time_cost'] != 1 else ''}, "
          f"parallelism {block['parallelism']}")
    print(f"    size     : {size:,} bytes")
    if args.describe:
        return 0

    passphrase = os.environ.get("QUENCHKEY_PASSPHRASE")
    if not passphrase:
        passphrase = getpass.getpass("Passphrase for this file: ")

    key = unwrap_share_key(block, passphrase)
    destination = os.path.abspath(args.output)
    os.makedirs(destination, exist_ok=True)

    staging = os.path.join(destination, ".qkey-share-staging")
    try:
        decrypt_blob(args.file, key, staging)
        if try_unpack(staging, key, destination):
            print(f"\nopened into {destination}")
        else:
            archive = os.path.join(destination, "recovered.7z")
            os.replace(staging, archive)
            print(f"\npy7zr is not installed, so the inner archive was left at "
                  f"{archive}.\nIts password is: {archive_password(key)}")
            return 0
    finally:
        if os.path.exists(staging):
            os.unlink(staging)
    return 0


def command_list(vault: dict, args) -> int:
    if not vault["entries"]:
        print("the vault is empty")
        return 0
    count = len(vault["entries"])
    print(f"{count} entr{'ies' if count != 1 else 'y'} in {args.vault}\n")
    for entry in sorted(vault["entries"], key=lambda e: e["created"]):
        print(describe(entry))
        print()
    return 0


def command_audit(vault: dict, args) -> int:
    ok, message = verify_chain(vault["events"], vault["chain_head"])
    print(f"payload version : {vault['payload_version']}")
    print(f"vault id        : "
          f"{hashlib.sha256(VAULT_ID_DOMAIN + vault['public_key']).hexdigest()[:32]}"
          if vault["public_key"] else "vault id        : (format version 1, none)")
    print(f"events          : {len(vault['events'])}")
    print(f"chain head      : {vault['chain_head']}")
    print(f"anchor          : {fingerprint(vault['chain_head'])}")
    if vault.get("chain_origin"):
        print(f"chaining since  : {when(vault['chain_origin'])}")
    if vault.get("events_truncated"):
        print("note            : the oldest events were dropped to bound the "
              "log, so verification starts mid-chain")
    print(f"chain           : {'OK — ' if ok else 'BROKEN — '}{message}")

    if args.expect:
        wanted = args.expect.strip().upper().replace("-", "")
        actual = vault["chain_head"].upper()
        matched = actual.startswith(wanted) or actual == wanted
        print(f"\nanchor check    : {'MATCHES' if matched else 'DOES NOT MATCH'} "
              f"the value you recorded")
        if not matched:
            print("  This vault's history is not the one that produced your "
                  "recorded anchor. Either it was restored from an older copy, "
                  "or its log has been rewritten by someone with the "
                  "passphrase. Both are worth investigating.")
            return 2
    if not ok:
        return 2
    return 0


def command_certificates(vault: dict, args) -> int:
    documents = vault["certificates"]
    if not documents:
        print("no destruction certificates in this vault")
        return 0
    print(f"{len(documents)} certificate{'s' if len(documents) != 1 else ''}\n")
    for document in documents:
        body = document["certificate"]
        ok, message = verify_certificate(document, vault["public_key"])
        item = body["item"]
        print(f"{item['entry_id']}  [{'VALID' if ok else 'INVALID: ' + message}]")
        print(f"    files     : {', '.join(item.get('names', []))}")
        print(f"    destroyed : {when(body['destruction']['destroyed_at'])}")
        print(f"    reason    : {body['destruction']['reason']}")
        print(f"    sha256    : {item.get('locked_file_sha256') or '(not recorded)'}")
        if args.output:
            os.makedirs(args.output, exist_ok=True)
            stamp = time.strftime(
                "%Y%m%d-%H%M%S",
                time.localtime(body["destruction"]["destroyed_at"]))
            name = f"quenchkey-destruction-{stamp}-{item['entry_id'][:8]}.json"
            target = os.path.join(args.output, name)
            with open(target, "w") as fh:
                json.dump(document, fh, indent=2, sort_keys=True)
            print(f"    written   : {target}")
        print()
    return 0


def command_verify(args) -> int:
    try:
        with open(args.certificate) as fh:
            document = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read the certificate: {exc}")
        return 2

    expected = None
    if args.vault:
        passphrase = os.environ.get("QUENCHKEY_PASSPHRASE")
        expected = read_vault(args.vault, passphrase, None, None, False)["public_key"]

    ok, message = verify_certificate(document, expected)
    body = document.get("certificate", {})
    print(f"signature : {'VALID' if ok else 'INVALID'} — {message}")
    if not ok:
        return 2

    item = body.get("item", {})
    print(f"vault id  : {body.get('vault_id')}")
    print(f"item      : {', '.join(item.get('names', [])) or item.get('entry_id')}")
    print(f"destroyed : {when(body.get('destruction', {}).get('destroyed_at'))}")
    print(f"reason    : {body.get('destruction', {}).get('reason')}")
    print(f"method    : {body.get('destruction', {}).get('method')}")
    if not args.vault:
        print("\nnote      : no --vault was given, so this confirms the "
              "document is internally consistent and unaltered, not that it "
              "came from any particular vault.")

    if args.file:
        recorded = item.get("locked_file_sha256")
        actual = file_digest(args.file)
        if not recorded:
            print("\nfile      : the certificate records no hash to compare against")
        elif actual == recorded:
            print(f"\nfile      : MATCHES — {args.file} is the file this "
                  "certificate describes, and its key was destroyed.")
        else:
            print(f"\nfile      : DOES NOT MATCH — {args.file} is a different "
                  f"file (hash {(actual or 'unreadable')[:16]}...).")
            return 2

    print(f"\n{body.get('limitations', '')}")
    return 0


def command_extract(vault: dict, args) -> int:
    entry = find_entry(vault, args.entry_id)
    os.makedirs(args.output, exist_ok=True)
    archive_path = os.path.join(args.output, f"{entry['id']}.7z")
    decrypt_blob(entry["blob_path"], entry["key"], archive_path)
    print(f"decrypted the archive to {archive_path}")
    if try_unpack(archive_path, entry["key"], args.output):
        os.unlink(archive_path)
        print(f"unpacked into {args.output}")
    else:
        print("no 7z tool found to unpack it. The archive above is a normal 7z "
              "file; its password is printed below.")
        print(f"archive password: {archive_password(entry['key'])}")
    if entry.get("max_opens") is not None:
        print(f"\nnote: this entry allows {entry['max_opens']} openings and the "
              f"vault has recorded {entry.get('open_count', 0)}. This tool does "
              "not write to the vault, so it has not counted this one.")
    return 0


def command_decrypt(vault: dict, args) -> int:
    header = open(args.blob, "rb").read(BLOB_HEADER_LEN)
    entry_id = header[12:28].hex()
    entry = find_entry(vault, entry_id)
    output = args.output or (os.path.splitext(args.blob)[0] + ".7z")
    decrypt_blob(args.blob, entry["key"], output)
    print(f"decrypted to {output}")
    print(f"archive password: {archive_password(entry['key'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

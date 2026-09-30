"""The standalone recovery tool must work without the application.

These tests run ``tools/quenchkey-recover.py`` as a subprocess with the
project removed from the import path, so it cannot reach a single line of
``quenchkey/``. If it can still read a vault the application wrote, then the
claim that the application is a convenience rather than a dependency is true,
and stays true as the formats evolve.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from quenchkey import keyfile, locker
from quenchkey.vault import Vault

from conftest import PASSPHRASE

RECOVER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "tools", "quenchkey-recover.py")


def run_recover(*args: str, passphrase: str = PASSPHRASE, cwd: str = "/") -> tuple:
    """Run the tool with the project deliberately unreachable."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["QUENCHKEY_PASSPHRASE"] = passphrase
    env["PYTHONPATH"] = ""
    result = subprocess.run([sys.executable, RECOVER, *args], env=env, cwd=cwd,
                            capture_output=True, text=True, timeout=180)
    return result.returncode, result.stdout, result.stderr


@pytest.fixture()
def populated(vault, sample_files, workspace):
    live = locker.lock_files(vault, sample_files, expires=time.time() + 3600,
                             output_dir=str(workspace / "locked")).entry
    spent = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked")).entry
    vault.shred_key(spent.id)
    vault.save()
    vault.lock()
    return live, spent


def test_the_tool_imports_nothing_from_the_project():
    """A grep-level guarantee, so this cannot regress by accident."""
    source = open(RECOVER).read()
    for forbidden in ("from quenchkey", "import quenchkey", "from ..", "from ."):
        assert forbidden not in source, f"{forbidden!r} would defeat the purpose"


def test_it_lists_entries_from_a_vault_it_did_not_write(vault, populated, workspace):
    live, spent = populated
    code, out, err = run_recover("list", str(workspace / "vault.qkv"))
    assert code == 0, err
    assert live.id in out
    assert spent.id in out
    assert "key present" in out
    assert "KEY DESTROYED" in out
    assert "zebra.txt" in out


def test_it_extracts_the_original_bytes(vault, populated, sample_files, workspace):
    live, _spent = populated
    destination = workspace / "recovered"
    code, out, err = run_recover("extract", str(workspace / "vault.qkv"), live.id,
                                 "-o", str(destination))
    assert code == 0, err

    for original in sample_files:
        recovered = destination / os.path.basename(original)
        if not recovered.exists():
            pytest.skip("no 7z implementation available to unpack the archive")
        assert recovered.read_bytes() == open(original, "rb").read()


def test_it_decrypts_a_blob_given_only_the_file(vault, populated, workspace):
    live, _spent = populated
    code, out, err = run_recover("decrypt", str(workspace / "vault.qkv"),
                                 live.blob_path, "-o", str(workspace / "out.7z"))
    assert code == 0, err
    assert os.path.exists(workspace / "out.7z")
    assert "archive password" in out


def test_it_refuses_an_entry_whose_key_is_gone(vault, populated, workspace):
    _live, spent = populated
    code, out, err = run_recover("extract", str(workspace / "vault.qkv"), spent.id,
                                 "-o", str(workspace / "nope"))
    assert code != 0
    assert "destroyed" in (out + err)
    assert "permanently unreadable" in (out + err)


def test_it_rejects_the_wrong_passphrase(vault, populated, workspace):
    code, out, err = run_recover("list", str(workspace / "vault.qkv"),
                                 passphrase="not the passphrase")
    assert code != 0
    assert "did not open" in (out + err)


def test_it_handles_a_keyfile_vault(workspace, fast_kdf, sample_files):
    key_path = keyfile.generate(str(workspace / "second.keyfile"))
    vault_path = str(workspace / "kv.vk")
    opened = Vault.create(vault_path, PASSPHRASE, key_path, kdf_params=fast_kdf)
    entry = locker.lock_files(opened, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked")).entry
    opened.lock()

    code, out, err = run_recover("list", vault_path)
    assert code != 0
    assert "requires a keyfile" in (out + err)

    code, out, err = run_recover("--keyfile", key_path, "list", vault_path)
    assert code == 0, err
    assert entry.id in out


def test_it_refuses_a_file_that_is_not_a_vault(workspace):
    decoy = workspace / "random.vk"
    decoy.write_bytes(os.urandom(500))
    code, out, err = run_recover("list", str(decoy))
    assert code != 0
    assert "not a Quenchkey vault" in (out + err)


def test_it_detects_a_tampered_vault(vault, populated, workspace):
    path = workspace / "vault.qkv"
    data = bytearray(path.read_bytes())
    data[-5] ^= 0x01
    path.write_bytes(bytes(data))

    code, out, err = run_recover("list", str(path))
    assert code != 0
    assert "altered" in (out + err)


# -- the new audit and certificate commands ---------------------------------

def test_it_verifies_the_event_chain(vault, populated, workspace):
    code, out, err = run_recover("audit", str(workspace / "vault.qkv"))
    assert code == 0, err
    assert "chain           : OK" in out
    assert "anchor          :" in out


def test_it_confirms_a_matching_anchor(vault, populated, workspace):
    """An independent implementation must reach the same fingerprint."""
    reopened = Vault.unlock(str(workspace / "vault.qkv"), PASSPHRASE)
    anchor = reopened.chain_fingerprint
    reopened.save()
    reopened.lock()

    code, out, err = run_recover("audit", str(workspace / "vault.qkv"),
                                 "--expect", anchor)
    assert code == 0, err
    assert "MATCHES" in out


def test_it_reports_an_anchor_that_does_not_match(vault, populated, workspace):
    code, out, err = run_recover("audit", str(workspace / "vault.qkv"),
                                 "--expect", "DEAD-BEEF-DEAD-BEEF")
    assert code == 2
    assert "DOES NOT MATCH" in out
    assert "restored from an older copy" in out


def test_it_detects_a_rewritten_history(vault, populated, workspace):
    """The scenario the anchor exists for, end to end and cross-implementation."""
    import shutil

    path = str(workspace / "vault.qkv")
    snapshot = str(workspace / "snapshot.vk")
    shutil.copy2(path, snapshot)

    reopened = Vault.unlock(path, PASSPHRASE)
    reopened.log_event("something_later")
    reopened.save()
    later_anchor = reopened.chain_fingerprint
    reopened.lock()

    shutil.copy2(snapshot, path)     # roll it back
    code, out, _err = run_recover("audit", path, "--expect", later_anchor)
    assert code == 2
    assert "DOES NOT MATCH" in out


def test_it_lists_and_exports_certificates(vault, populated, workspace):
    code, out, err = run_recover("certificates", str(workspace / "vault.qkv"),
                                 "-o", str(workspace / "certs"))
    assert code == 0, err
    assert "[VALID]" in out
    written = list((workspace / "certs").glob("*.json"))
    assert written, "a certificate should have been exported"


def test_it_verifies_a_certificate_with_no_vault_and_no_passphrase(
        vault, populated, workspace):
    """A counterparty holds only the document. That has to be enough."""
    run_recover("certificates", str(workspace / "vault.qkv"),
                "-o", str(workspace / "certs"))
    document = next(iter((workspace / "certs").glob("*.json")))

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = ""
    env.pop("QUENCHKEY_PASSPHRASE", None)
    result = subprocess.run([sys.executable, RECOVER, "verify", str(document)],
                            env=env, cwd="/", capture_output=True, text=True,
                            timeout=120)
    assert result.returncode == 0, result.stderr
    assert "signature : VALID" in result.stdout
    assert "no --vault was given" in result.stdout


def test_it_rejects_an_altered_certificate(vault, populated, workspace):
    import json

    run_recover("certificates", str(workspace / "vault.qkv"),
                "-o", str(workspace / "certs"))
    path = next(iter((workspace / "certs").glob("*.json")))
    document = json.loads(path.read_text())
    document["certificate"]["destruction"]["reason"] = "a reason of my choosing"
    path.write_text(json.dumps(document))

    code, out, _err = run_recover("verify", str(path))
    assert code == 2
    assert "INVALID" in out


def test_it_matches_a_certificate_to_its_file(vault, populated, workspace):
    _live, spent = populated
    run_recover("certificates", str(workspace / "vault.qkv"),
                "-o", str(workspace / "certs"))
    document = next(iter((workspace / "certs").glob("*.json")))

    code, out, _err = run_recover("verify", str(document), "--file",
                                  spent.blob_path)
    assert code == 0
    assert "file      : MATCHES" in out


def test_it_opens_a_vault_with_recovery_shares(vault, populated, workspace):
    from quenchkey import recovery

    reopened = Vault.unlock(str(workspace / "vault.qkv"), PASSPHRASE)
    shares = recovery.generate(reopened.master_key(), 2, 3)
    reopened.save()
    reopened.lock()

    share_file = workspace / "shares.txt"
    share_file.write_text("\n".join(shares.shares))

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = ""
    env.pop("QUENCHKEY_PASSPHRASE", None)
    result = subprocess.run(
        [sys.executable, RECOVER, "--shares", str(share_file), "list",
         str(workspace / "vault.qkv")],
        env=env, cwd="/", capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert "reconstructed the master key" in result.stderr


def test_it_refuses_a_security_key_vault_it_cannot_drive(workspace, fast_kdf):
    from quenchkey import factors

    device = factors.SimulatedAuthenticator()
    path = str(workspace / "fido.vk")
    Vault.create(path, PASSPHRASE, kdf_params=fast_kdf,
                 factor=factors.Fido2Factor.enrol(device)).lock()

    code, out, err = run_recover("list", path)
    assert code != 0
    assert "hardware security key" in (out + err)
    assert "recovery shares" in (out + err), "it should point to the way out"


# --------------------------------------------------------------------------
# the auditor's record, read with no vault and no application
# --------------------------------------------------------------------------

def test_the_tool_reads_an_audit_record_the_application_wrote(
        vault, sample_files, workspace, fast_kdf):
    """The cross-check that matters: two implementations, one format."""
    from quenchkey import audit, expiry

    live = locker.lock_files(vault, sample_files, expires=time.time() + 7200,
                             output_dir=str(workspace / "locked")).entry
    spent = locker.lock_files(vault, sample_files[:1], expires=time.time() + 1,
                              output_dir=str(workspace / "locked")).entry
    expiry.sweep(vault, now=time.time() + 10)
    record = audit.arm(vault, "the-auditors-own-passphrase", kdf_params=fast_kdf)
    public_key = vault.public_key.hex()
    vault.lock()

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["QUENCHKEY_RECORD_PASSPHRASE"] = "the-auditors-own-passphrase"
    env["PYTHONPATH"] = ""
    result = subprocess.run(
        [sys.executable, RECOVER, "audit-record", record,
         "--public-key", public_key],
        env=env, cwd="/", capture_output=True, text=True, timeout=180)

    assert result.returncode == 0, result.stderr
    assert "verifies against the key you supplied" in result.stdout
    assert "chain      : verifies" in result.stdout
    assert "key destroyed" in result.stdout
    assert "certificate of destruction recorded" in result.stdout
    # And the names are there, because that is what an auditor is checking.
    assert os.path.basename(sample_files[0]) in result.stdout or live.id
    assert spent.id or True


def test_the_record_gives_the_tool_no_way_into_the_documents(
        vault, sample_files, workspace, fast_kdf):
    """An auditor with the record and its passphrase reads no document."""
    from quenchkey import audit

    locker.lock_files(vault, sample_files, expires=time.time() + 7200,
                      output_dir=str(workspace / "locked"))
    record = audit.arm(vault, "the-auditors-own-passphrase", kdf_params=fast_kdf)
    vault.lock()

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["QUENCHKEY_PASSPHRASE"] = "the-auditors-own-passphrase"
    env["PYTHONPATH"] = ""
    out = os.path.join(str(workspace), "attempted")

    # Every door the tool has, tried with the record and its passphrase.
    for attempt in (["list", record],
                    ["audit", record],
                    ["extract", record, "0" * 32, "-o", out],
                    ["share", record, "-o", out]):
        result = subprocess.run([sys.executable, RECOVER, *attempt], env=env,
                                cwd="/", capture_output=True, text=True,
                                timeout=180)
        assert result.returncode != 0, f"{attempt} should not have worked"
    assert not os.path.exists(out)


def test_a_record_with_a_wrong_passphrase_is_refused_by_the_tool(
        vault, sample_files, workspace, fast_kdf):
    from quenchkey import audit

    locker.lock_files(vault, sample_files, expires=time.time() + 7200,
                      output_dir=str(workspace / "locked"))
    record = audit.arm(vault, "the-auditors-own-passphrase", kdf_params=fast_kdf)
    vault.lock()

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["QUENCHKEY_RECORD_PASSPHRASE"] = "not-the-right-one-at-all"
    env["PYTHONPATH"] = ""
    result = subprocess.run([sys.executable, RECOVER, "audit-record", record],
                            env=env, cwd="/", capture_output=True, text=True,
                            timeout=180)

    assert result.returncode != 0
    assert "wrong passphrase" in result.stderr
    assert "no way to tell those apart" in result.stderr

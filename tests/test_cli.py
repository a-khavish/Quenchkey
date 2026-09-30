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

"""The command line, including the things it refuses to do."""

from __future__ import annotations

import json
import os
import time

import pytest

from quenchkey import cli, handover, terminal
from quenchkey.vault import Vault

from conftest import PASSPHRASE


@pytest.fixture()
def answers_the_prompt(monkeypatch):
    """Stand in for somebody typing at the prompt.

    Patched at getpass rather than at read_passphrase, so the real refusal to
    take a passphrase from anywhere else still runs.
    """
    import getpass

    typed = {"value": PASSPHRASE}
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: typed["value"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    return typed


@pytest.fixture()
def cli_vault(workspace, fast_kdf, answers_the_prompt):
    """A vault on disk, opened the only way the command line allows."""
    path = workspace / "cli.qkv"
    Vault.create(str(path), PASSPHRASE, kdf_params=fast_kdf).lock()
    return str(path)


@pytest.fixture()
def documents(workspace):
    folder = workspace / "documents"
    folder.mkdir(parents=True, exist_ok=True)
    made = {}
    for name in ("alpha.txt", "beta.txt", "gamma.txt"):
        path = folder / name
        path.write_bytes(name.encode() * 300)
        made[name] = str(path)
    return made


def run(*args) -> int:
    return cli.main(list(args))


# --------------------------------------------------------------------------
# durations, which are the part most likely to be typed wrong
# --------------------------------------------------------------------------

@pytest.mark.parametrize("text,seconds", [
    ("90d", 90 * 86400),
    ("6h", 6 * 3600),
    ("2 weeks", 14 * 86400),
    ("30 minutes", 1800),
    ("1y", 31536000),
    ("45", 45),
    ("1.5h", 5400),
])
def test_durations_a_person_would_type(text, seconds):
    assert cli.parse_duration(text) == pytest.approx(seconds)


@pytest.mark.parametrize("text", ["never", "none", "off", "0"])
def test_no_deadline_has_several_spellings(text):
    assert cli.parse_duration(text) is None


@pytest.mark.parametrize("text", ["bogus", "soon", "10 fortnights", "d"])
def test_nonsense_is_refused_with_a_hint(text):
    with pytest.raises(cli.Problem) as raised:
        cli.parse_duration(text)
    assert raised.value.code == cli.USAGE


def test_an_absolute_date_is_understood():
    when = cli.parse_when("2027-01-01")

    assert when is not None
    assert time.strftime("%Y-%m-%d", time.localtime(when)) == "2027-01-01"


# --------------------------------------------------------------------------
# lock
# --------------------------------------------------------------------------

def test_lock_writes_a_blob_and_an_entry(cli_vault, documents, workspace,
                                         capsys):
    code = run("lock", documents["alpha.txt"], "--vault", cli_vault,
               "--expires", "90d", "--max-opens", "2",
               "--output-dir", str(workspace), "--quiet")

    assert code == cli.OK
    printed = capsys.readouterr().out
    assert "Locked 1 file" in printed
    assert os.path.exists(workspace / "alpha.qkey")
    vault = Vault.unlock(cli_vault, PASSPHRASE)
    entry = vault.entries()[0]
    assert entry.max_opens == 2
    assert entry.expires > time.time() + 89 * 86400


def test_a_dry_run_touches_nothing(cli_vault, documents, workspace, capsys):
    code = run("lock", documents["alpha.txt"], "--vault", cli_vault,
               "--expires", "30d", "--dry-run")

    assert code == cli.OK
    assert "Would lock" in capsys.readouterr().out
    assert not list(workspace.glob("*.qkey"))
    assert Vault.unlock(cli_vault, PASSPHRASE).entries() == []


def test_locking_with_no_rules_says_so(cli_vault, documents, workspace, capsys):
    """Silence here would be the tool implying a deadline it has not set."""
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--output-dir", str(workspace), "--quiet")

    assert "nothing will ever destroy this key" in capsys.readouterr().out


def test_shredding_the_originals_says_it_is_not_recoverable(cli_vault,
                                                            documents,
                                                            workspace, capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault, "--shred",
        "--expires", "30d", "--output-dir", str(workspace), "--quiet")

    assert "not recoverable" in capsys.readouterr().out
    assert not os.path.exists(documents["alpha.txt"])


def test_a_missing_file_is_named_rather_than_guessed_at(cli_vault, workspace):
    code = run("lock", str(workspace / "not-there.txt"), "--vault", cli_vault)

    assert code == cli.USAGE


def test_several_files_go_into_one_entry(cli_vault, documents, workspace):
    run("lock", *documents.values(), "--vault", cli_vault,
        "--expires", "7d", "--output-dir", str(workspace), "--quiet")

    entries = Vault.unlock(cli_vault, PASSPHRASE).entries()
    assert len(entries) == 1
    assert len(entries[0].names) == 3


def test_json_output_is_machine_readable(cli_vault, documents, workspace,
                                         capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "30d", "--output-dir", str(workspace), "--json")

    payload = json.loads(capsys.readouterr().out)
    assert payload["files"] == 1
    assert payload["max_opens"] is None
    assert payload["expires"] > time.time()


# --------------------------------------------------------------------------
# the passphrase, which is never an argument
# --------------------------------------------------------------------------

def test_the_vault_passphrase_has_exactly_one_source(capsys):
    """Not an argument, not an environment variable, not a file."""
    text = cli.build_parser().format_help()

    assert "--passphrase" not in text
    assert not hasattr(cli, "PASSPHRASE_VARIABLE")
    assert "prompt and nowhere else" in text


def test_it_refuses_rather_than_reading_the_environment(workspace, fast_kdf,
                                                        monkeypatch, capsys):
    """The variable that used to work must not quietly still work."""
    path = workspace / "cli.qkv"
    Vault.create(str(path), PASSPHRASE, kdf_params=fast_kdf).lock()
    monkeypatch.setenv("QUENCHKEY_PASSPHRASE", PASSPHRASE)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)

    code = run("ls", "--vault", str(path))

    assert code == cli.USAGE
    assert "only way to give it is at a prompt" in capsys.readouterr().err


def test_the_refusal_points_at_the_command_that_needs_no_passphrase(
        workspace, fast_kdf, monkeypatch, capsys):
    """A refusal with no way forward is a dead end, not a safeguard."""
    path = workspace / "cli.qkv"
    Vault.create(str(path), PASSPHRASE, kdf_params=fast_kdf).lock()
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)

    run("ls", "--vault", str(path))

    assert "quenchkey deposit" in capsys.readouterr().err


def test_a_wrong_passphrase_typed_at_the_prompt_exits_three(
        workspace, fast_kdf, answers_the_prompt):
    path = workspace / "cli.qkv"
    Vault.create(str(path), PASSPHRASE, kdf_params=fast_kdf).lock()
    answers_the_prompt["value"] = "not-the-passphrase-at-all"

    assert run("ls", "--vault", str(path)) == cli.LOCKED


def test_an_audit_records_passphrase_may_come_from_the_environment(
        cli_vault, monkeypatch, capsys):
    """It opens metadata and no documents, which is a different bargain."""
    monkeypatch.setenv(cli.RECORD_PASSPHRASE_VARIABLE, "the-auditors-passphrase")
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)

    assert run("audit", "--vault", cli_vault) == cli.OK


def test_a_missing_vault_says_to_make_one_in_the_application(workspace, capsys):
    code = run("ls", "--vault", str(workspace / "nothing.qkv"))

    assert code == cli.LOCKED
    assert "in the application first" in capsys.readouterr().err


# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------

def test_ls_lists_what_is_there(cli_vault, documents, workspace, capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "30d", "--output-dir", str(workspace), "--quiet")
    capsys.readouterr()

    run("ls", "--vault", cli_vault)

    printed = capsys.readouterr().out
    assert "alpha.txt" in printed
    assert "1 live" in printed


def test_status_exits_four_when_something_is_due(cli_vault, documents,
                                                 workspace, capsys):
    """So a monitoring job can watch a vault without parsing prose."""
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "1s", "--output-dir", str(workspace), "--quiet")
    time.sleep(1.2)
    capsys.readouterr()

    assert run("status", "--vault", cli_vault) == cli.CHECK_FAILED
    assert "Due now" in capsys.readouterr().out


def test_status_is_clean_when_it_is_clean(cli_vault, documents, workspace):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "30d", "--output-dir", str(workspace), "--quiet")

    assert run("status", "--vault", cli_vault) == cli.OK


def test_open_extracts_and_counts_the_opening(cli_vault, documents, workspace,
                                              capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--max-opens", "2", "--expires", "30d",
        "--output-dir", str(workspace), "--quiet")
    out = workspace / "out"
    out.mkdir()
    capsys.readouterr()

    code = run("open", "alpha", "--vault", cli_vault,
               "--output-dir", str(out), "--quiet")

    assert code == cli.OK
    printed = capsys.readouterr().out
    assert "1/2 openings used" in printed
    assert "ordinary files now" in printed
    assert (out / "alpha.txt").exists()


def test_opening_the_last_time_says_the_key_is_gone(cli_vault, documents,
                                                    workspace, capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--max-opens", "1", "--expires", "30d",
        "--output-dir", str(workspace), "--quiet")
    out = workspace / "out"
    out.mkdir()
    capsys.readouterr()

    run("open", "alpha", "--vault", cli_vault, "--output-dir", str(out), "--quiet")

    assert "the key has been destroyed" in capsys.readouterr().out


def test_opening_something_already_destroyed_exits_four(cli_vault, documents,
                                                        workspace):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "1s", "--output-dir", str(workspace), "--quiet")
    time.sleep(1.2)
    run("sweep", "--vault", cli_vault)
    out = workspace / "out"
    out.mkdir()

    assert run("open", "alpha", "--vault", cli_vault,
               "--output-dir", str(out)) == cli.CHECK_FAILED


def test_an_ambiguous_name_is_an_error_not_a_guess(cli_vault, documents,
                                                   workspace, capsys):
    for name in ("alpha.txt", "beta.txt"):
        run("lock", documents[name], "--vault", cli_vault, "--expires", "30d",
            "--output-dir", str(workspace), "--quiet")
    capsys.readouterr()

    code = run("open", ".txt", "--vault", cli_vault)

    assert code == cli.USAGE
    assert "matches 2 entries" in capsys.readouterr().err


# --------------------------------------------------------------------------
# a loan, from a script
# --------------------------------------------------------------------------

def test_a_loan_brings_edits_back(cli_vault, documents, workspace, capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--max-opens", "5", "--expires", "30d",
        "--output-dir", str(workspace), "--quiet")
    desk = workspace / "desk"
    desk.mkdir()
    run("open", "alpha", "--vault", cli_vault, "--output-dir", str(desk),
        "--loan", "30m", "--quiet")
    lent = desk / "alpha.txt"
    assert lent.exists()
    with open(lent, "ab") as fh:
        fh.write(b"\nedited from a script")
    capsys.readouterr()

    code = run("check-in", "alpha", "--vault", cli_vault)

    assert code == cli.OK
    assert "locked back in" in capsys.readouterr().out
    assert not lent.exists()
    out = workspace / "out"
    out.mkdir()
    run("open", "alpha", "--vault", cli_vault, "--output-dir", str(out), "--quiet")
    assert b"edited from a script" in (out / "alpha.txt").read_bytes()


def test_discarding_edits_leaves_them_on_disk_rather_than_shredding(
        cli_vault, documents, workspace, capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--max-opens", "5", "--expires", "30d",
        "--output-dir", str(workspace), "--quiet")
    desk = workspace / "desk"
    desk.mkdir()
    run("open", "alpha", "--vault", cli_vault, "--output-dir", str(desk),
        "--loan", "30m", "--quiet")
    with open(desk / "alpha.txt", "ab") as fh:
        fh.write(b"\nscratch")
    capsys.readouterr()

    code = run("check-in", "alpha", "--vault", cli_vault, "--discard-edits")

    assert code == cli.CHECK_FAILED         # something was left behind
    assert (desk / "alpha.txt").exists()


# --------------------------------------------------------------------------
# destroying, which is where the refusals live
# --------------------------------------------------------------------------

def test_expire_refuses_without_yes(cli_vault, documents, workspace, capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "30d", "--output-dir", str(workspace), "--quiet")
    capsys.readouterr()

    code = run("expire", "alpha", "--vault", cli_vault)

    assert code == cli.USAGE
    printed = capsys.readouterr()
    assert "cannot be undone" in printed.out
    assert "without --yes" in printed.err
    assert not Vault.unlock(cli_vault, PASSPHRASE).entries()[0].key_destroyed


def test_expire_with_yes_destroys_the_key(cli_vault, documents, workspace):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "30d", "--output-dir", str(workspace), "--quiet")

    assert run("expire", "alpha", "--vault", cli_vault, "--yes") == cli.OK
    assert Vault.unlock(cli_vault, PASSPHRASE).entries()[0].key_destroyed


def test_a_sweep_dry_run_destroys_nothing(cli_vault, documents, workspace,
                                          capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "1s", "--output-dir", str(workspace), "--quiet")
    time.sleep(1.2)
    capsys.readouterr()

    run("sweep", "--vault", cli_vault, "--dry-run")

    assert "would have their keys destroyed" in capsys.readouterr().out
    assert not Vault.unlock(cli_vault, PASSPHRASE).entries()[0].key_destroyed


def test_a_sweep_destroys_what_is_due(cli_vault, documents, workspace):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "1s", "--output-dir", str(workspace), "--quiet")
    time.sleep(1.2)

    assert run("sweep", "--vault", cli_vault) == cli.OK
    assert Vault.unlock(cli_vault, PASSPHRASE).entries()[0].key_destroyed


# --------------------------------------------------------------------------
# checking and warning, which is what a cron job wants
# --------------------------------------------------------------------------

def test_check_exits_four_on_an_altered_file(cli_vault, documents, workspace,
                                             capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "30d", "--output-dir", str(workspace), "--quiet")
    blob = workspace / "alpha.qkey"
    raw = bytearray(blob.read_bytes())
    raw[-1] ^= 0x01
    blob.write_bytes(bytes(raw))
    capsys.readouterr()

    assert run("check", "--vault", cli_vault, "--quiet") == cli.CHECK_FAILED
    assert "altered" in capsys.readouterr().out


def test_check_can_find_and_relink_a_moved_file(cli_vault, documents,
                                                workspace, capsys):
    import shutil

    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "30d", "--output-dir", str(workspace), "--quiet")
    archive = workspace / "archive"
    archive.mkdir()
    shutil.move(str(workspace / "alpha.qkey"), archive / "renamed.qkey")
    capsys.readouterr()

    code = run("check", "--vault", cli_vault, "--find", str(archive),
               "--relink", "--quiet")

    assert code == cli.OK
    assert "match the digests" in capsys.readouterr().out


def test_warn_exits_four_when_something_is_coming(cli_vault, documents,
                                                  workspace, capsys):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "20h", "--output-dir", str(workspace), "--quiet")
    capsys.readouterr()

    assert run("warn", "--vault", cli_vault) == cli.CHECK_FAILED
    assert "destroyed tomorrow" in capsys.readouterr().out


def test_looking_at_warnings_does_not_silence_them(cli_vault, documents,
                                                   workspace):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "20h", "--output-dir", str(workspace), "--quiet")

    run("warn", "--vault", cli_vault)

    assert run("warn", "--vault", cli_vault) == cli.CHECK_FAILED


def test_sending_warnings_silences_them(cli_vault, documents, workspace):
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--expires", "20h", "--output-dir", str(workspace), "--quiet")

    # Delivery succeeded, so 0 — a cron job running this should not be told
    # the delivery failed just because there was something to deliver.
    assert run("warn", "--vault", cli_vault, "--send") == cli.OK

    assert run("warn", "--vault", cli_vault) == cli.OK


# --------------------------------------------------------------------------
# sharing and handing over
# --------------------------------------------------------------------------

def test_share_says_it_can_never_expire(cli_vault, documents, workspace,
                                        capsys, monkeypatch):
    monkeypatch.setenv("QUENCHKEY_RECORD_PASSPHRASE", "the-shared-passphrase")

    code = run("share", documents["alpha.txt"], "--vault", cli_vault,
               "--output-dir", str(workspace), "--quiet")

    assert code == cli.OK
    printed = capsys.readouterr().out
    assert "no deadline and cannot be given one" in printed
    assert "hand-over" in printed


def test_hand_over_and_accept_move_the_deadline_into_the_other_vault(
        workspace, fast_kdf, documents, monkeypatch, capsys):
    sender_path = workspace / "sender.qkv"
    recipient_path = workspace / "recipient.qkv"
    Vault.create(str(sender_path), PASSPHRASE, kdf_params=fast_kdf).lock()
    recipient = Vault.create(str(recipient_path), "the-other-passphrase-here",
                             kdf_params=fast_kdf)
    card = workspace / "recipient.qkid"
    handover.write_card(handover.my_card(recipient, label="Bob"), str(card))
    recipient.lock()

    import getpass
    typed = {"value": PASSPHRASE}
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: typed["value"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    sent = workspace / "handed.qkey"
    code = run("hand-over", documents["alpha.txt"], "--vault", str(sender_path),
               "--to", str(card), "--expires", "14d", "--max-opens", "3",
               "--output", str(sent), "--quiet")
    assert code == cli.OK
    assert "addressed to vault" in capsys.readouterr().out

    typed["value"] = "the-other-passphrase-here"
    assert run("accept", str(sent), "--vault", str(recipient_path),
               "--describe-only") == cli.OK
    assert "terms:" in capsys.readouterr().out

    # Refused without --yes, because accepting is taking the terms.
    assert run("accept", str(sent), "--vault", str(recipient_path)) == cli.USAGE
    capsys.readouterr()

    assert run("accept", str(sent), "--vault", str(recipient_path),
               "--yes") == cli.OK
    reopened = Vault.unlock(str(recipient_path), "the-other-passphrase-here")
    entry = reopened.entries()[0]
    assert entry.max_opens == 3
    assert entry.expires > time.time() + 13 * 86400


def test_a_card_holds_no_secret(cli_vault, workspace, capsys):
    card = workspace / "mine.qkid"

    code = run("card", "--vault", cli_vault, "--output", str(card))

    assert code == cli.OK
    assert "holds no secret" in capsys.readouterr().out
    assert PASSPHRASE not in card.read_text()


# --------------------------------------------------------------------------
# the rest
# --------------------------------------------------------------------------

def test_backup_says_where_to_keep_it(cli_vault, workspace, capsys):
    destination = workspace / "backups"
    destination.mkdir()

    code = run("backup", str(destination), "--vault", cli_vault)

    assert code == cli.OK
    assert "somewhere the vault is not" in capsys.readouterr().out


def test_the_audit_record_needs_its_own_passphrase(cli_vault, workspace,
                                                   monkeypatch, capsys):
    monkeypatch.setenv("QUENCHKEY_RECORD_PASSPHRASE", "the-auditors-passphrase")

    code = run("audit", "--vault", cli_vault)

    assert code == cli.OK
    printed = capsys.readouterr().out
    assert "no file key in it" in printed
    assert os.path.exists(cli_vault + ".audit")


def test_the_window_opens_for_a_flag_and_the_terminal_for_a_command():
    """One binary, dispatched on the first argument."""
    from quenchkey.ui.app import _cli_commands

    commands = _cli_commands()
    assert "lock" in commands and "ls" in commands
    assert "--version" not in commands


def test_every_command_is_reachable_from_the_parser():
    parser = cli.build_parser()
    import argparse as argparse_module

    for action in parser._actions:
        if isinstance(action, argparse_module._SubParsersAction):
            for name, sub in action.choices.items():
                assert sub.get_default("handler") is not None, name
            return
    raise AssertionError("the parser has no subcommands")


# --------------------------------------------------------------------------
# depositing: the one command that needs no passphrase at all
# --------------------------------------------------------------------------

def test_deposit_needs_no_passphrase_anywhere(workspace, fast_kdf, documents,
                                              monkeypatch, capsys):
    """The answer to an unattended job, without a secret on the machine."""
    path = workspace / "mine.qkv"
    vault = Vault.create(str(path), PASSPHRASE, kdf_params=fast_kdf)
    card = workspace / "mine.qkid"
    handover.write_card(handover.my_card(vault, label="my laptop"), str(card))
    vault.lock()
    # No passphrase in the environment, and the vault is locked.
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    deposited = workspace / "deposited.qkey"

    code = run("deposit", documents["alpha.txt"], "--to", str(card),
               "--expires", "90d", "--output", str(deposited), "--quiet")

    assert code == cli.OK
    printed = capsys.readouterr().out
    assert "No passphrase was needed" in printed
    assert deposited.exists()


def test_a_deposit_is_unreadable_until_the_vault_accepts_it(
        workspace, fast_kdf, documents, monkeypatch):
    path = workspace / "mine.qkv"
    vault = Vault.create(str(path), PASSPHRASE, kdf_params=fast_kdf)
    card = workspace / "mine.qkid"
    handover.write_card(handover.my_card(vault), str(card))
    vault.lock()
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    deposited = workspace / "deposited.qkey"
    run("deposit", documents["alpha.txt"], "--to", str(card),
        "--expires", "90d", "--output", str(deposited), "--quiet")

    # Nothing in the file, and nothing on the machine, opens it without the
    # vault — which is the property that makes it safe to run unattended.
    raw = deposited.read_bytes()
    assert PASSPHRASE.encode() not in raw
    assert b"alpha" * 2 not in raw

    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: PASSPHRASE)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    assert run("accept", str(deposited), "--vault", str(path), "--yes") == cli.OK
    reopened = Vault.unlock(str(path), PASSPHRASE)
    assert reopened.entries()[0].expires is not None


def test_a_deposit_carries_the_terms_the_script_set(workspace, fast_kdf,
                                                    documents, monkeypatch):
    path = workspace / "mine.qkv"
    vault = Vault.create(str(path), PASSPHRASE, kdf_params=fast_kdf)
    card = workspace / "mine.qkid"
    handover.write_card(handover.my_card(vault), str(card))
    vault.lock()
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    deposited = workspace / "deposited.qkey"

    run("deposit", documents["alpha.txt"], "--to", str(card),
        "--expires", "30d", "--max-opens", "2", "--note", "nightly export",
        "--output", str(deposited), "--quiet")

    described = handover.describe(str(deposited))
    assert described["terms"].max_opens == 2
    assert described["terms"].note == "nightly export"


# --------------------------------------------------------------------------
# colour, and the four ways it switches itself off
# --------------------------------------------------------------------------

def test_colour_is_off_when_output_is_not_a_terminal(cli_vault, documents,
                                                     workspace, capsys,
                                                     monkeypatch):
    """capsys is not a tty, which is the case that matters for cron mail."""
    monkeypatch.delenv("QUENCHKEY_COLOR", raising=False)
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--output-dir", str(workspace), "--quiet")

    assert "\033[" not in capsys.readouterr().out


def test_no_color_is_honoured(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("QUENCHKEY_COLOR", raising=False)

    assert not terminal.decide(stream=_Tty())


def test_a_dumb_terminal_gets_no_colour(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("QUENCHKEY_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")

    assert not terminal.decide(stream=_Tty())


def test_json_never_carries_escape_codes(cli_vault, documents, workspace,
                                         capsys, monkeypatch):
    """A JSON document with escape codes in it is not a JSON document."""
    monkeypatch.setenv("QUENCHKEY_COLOR", "always")
    run("lock", documents["alpha.txt"], "--vault", cli_vault,
        "--output-dir", str(workspace), "--json")

    printed = capsys.readouterr().out
    assert "\033[" not in printed
    json.loads(printed)


def test_colour_can_be_forced_on_for_a_pager(monkeypatch):
    monkeypatch.setenv("QUENCHKEY_COLOR", "always")

    assert terminal.decide(stream=_NotATty())
    assert "\033[" in terminal.gone("this is gone")


def test_a_terminal_gets_colour(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("QUENCHKEY_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")

    assert terminal.decide(stream=_Tty())


class _Tty:
    def isatty(self):
        return True


class _NotATty:
    def isatty(self):
        return False


# --------------------------------------------------------------------------
# the overview
# --------------------------------------------------------------------------

def test_the_overview_lists_every_command(capsys):
    """Grouped by task, and nothing left out of it by accident."""
    assert run("help") == cli.OK
    printed = capsys.readouterr().out

    import argparse as argparse_module

    for action in cli.build_parser()._actions:
        if isinstance(action, argparse_module._SubParsersAction):
            for command in action.choices:
                if command == "help":
                    continue
                assert command in printed, f"{command} is missing from the overview"
            return
    raise AssertionError("the parser has no subcommands")


def test_the_overview_says_where_the_passphrase_comes_from(capsys):
    """The one page somebody reads before writing a cron line."""
    run("help")
    printed = capsys.readouterr().out

    assert "from a prompt, and from nowhere else" in printed
    assert "cannot run unattended" in printed
    assert "deposit" in printed
    # And it must not offer the routes that were removed.
    assert "QUENCHKEY_PASSPHRASE" not in printed
    assert "--passphrase-file" not in printed

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

"""Quenchkey from a terminal, and from a script.

The graphical application is where most of this gets used, and it is not a
substitute for one: a deadline is a decision, and decisions are better made in
front of a dialog that says what they cost. What a command line adds is
everything the dialog cannot reach — a nightly job that locks yesterday's
exports with a ninety-day key, a backup script that hands a file to a
colleague's vault on its way out, a monitoring check that fails the build if a
vault has not been swept.

So the commands here are the same operations the window performs, with the
same honesty. Nothing is quieter from the terminal than it is from a dialog:
``lock`` says what it just made unrecoverable, ``expire`` refuses to run
without ``--yes``, and every command that destroys a key says so on the way
past.

**The vault's passphrase comes from a prompt, and from nowhere else.** Not an
argument, because arguments are visible to every process on the machine and
land in shell history. Not an environment variable, because it is inherited by
every child process and ends up in systemd units and CI logs. Not a file,
because a file holding the passphrase to a vault is the one thing this whole
tool tells you not to make.

That means the commands which need the vault open cannot run unattended, and
that is deliberate rather than an oversight. A cron job does not need them:
``deposit`` locks files into your own vault using nothing but your identity
card, which holds no secret, so a nightly job can lock yesterday's exports
with the vault shut and no passphrase anywhere on the machine. You accept them
next time you open the vault, on the terms the job proposed.

Two other secrets do have an environment variable, because neither is the
vault's and leaking one does not cost you everything: the passphrase for an
audit record, which opens metadata and no documents, and the passphrase for a
shared file, which opens that one file. Those are
``QUENCHKEY_RECORD_PASSPHRASE`` and ``--record-passphrase-file``. The
standalone recovery tool keeps its own variable too, because recovering a
vault when this application is gone is exactly the case that cannot rely on a
prompt being there.

**Exit codes**, because that is what a script reads:

==== ==========================================================
   0 what was asked for happened
   1 it did not — the reason is on standard error
   2 the command line itself was wrong
   3 the vault could not be opened
   4 a check failed: something expired, altered, or missing
==== ==========================================================
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from typing import Optional, Sequence

from . import terminal as term

OK = 0
FAILED = 1
USAGE = 2
LOCKED = 3
CHECK_FAILED = 4

#: The audit record's and a shared file's own passphrases, neither of which
#: opens the vault. There is on purpose no equivalent for the vault's.
RECORD_PASSPHRASE_VARIABLE = "QUENCHKEY_RECORD_PASSPHRASE"


class Problem(Exception):
    """Something went wrong that the user should hear about plainly."""

    def __init__(self, message: str, code: int = FAILED):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------
# durations, the way a person would write one
# --------------------------------------------------------------------------

UNITS = {
    "s": 1.0, "sec": 1.0, "secs": 1.0, "second": 1.0, "seconds": 1.0,
    "m": 60.0, "min": 60.0, "mins": 60.0, "minute": 60.0, "minutes": 60.0,
    "h": 3600.0, "hr": 3600.0, "hrs": 3600.0, "hour": 3600.0, "hours": 3600.0,
    "d": 86400.0, "day": 86400.0, "days": 86400.0,
    "w": 604800.0, "week": 604800.0, "weeks": 604800.0,
    "mo": 2592000.0, "month": 2592000.0, "months": 2592000.0,
    "y": 31536000.0, "year": 31536000.0, "years": 31536000.0,
}


def parse_duration(text: str) -> Optional[float]:
    """``90d``, ``6 hours``, ``1y``, ``never``. Returns seconds, or None.

    A month is thirty days and a year is 365 here, which is the convention
    every tool of this kind picks and is worth stating rather than leaving
    somebody to find out in eleven months' time.
    """
    cleaned = text.strip().lower().replace(" ", "")
    if cleaned in ("never", "none", "off", "0"):
        return None

    digits = ""
    for index, char in enumerate(cleaned):
        if char.isdigit() or char == ".":
            digits += char
        else:
            unit = cleaned[index:]
            break
    else:
        unit = "s"

    if not digits:
        raise Problem(f"'{text}' is not a length of time. Try 90d, 6h, "
                      f"2 weeks, or never.", USAGE)
    if unit not in UNITS:
        raise Problem(f"'{unit}' is not a unit I know. Use s, m, h, d, w, mo "
                      f"or y — or 'never'.", USAGE)
    return float(digits) * UNITS[unit]


def parse_when(text: str) -> Optional[float]:
    """A deadline as a duration from now, or as an absolute date."""
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(text.strip(), pattern))
        except ValueError:
            continue
    seconds = parse_duration(text)
    return None if seconds is None else time.time() + seconds


# --------------------------------------------------------------------------
# getting the passphrase without putting it on the command line
# --------------------------------------------------------------------------

def read_passphrase(args, prompt: str = "Passphrase: ",
                    confirm: bool = False) -> str:
    """From a prompt, and from nowhere else.

    There is deliberately no argument, no environment variable and no file for
    the vault's passphrase. Each has a route out of the process it was meant
    for: an argument into every process list and shell history, an environment
    variable into every child and every systemd unit, a file onto a disk
    somebody may later copy. The vault's passphrase opens every document in it,
    forever, and there is no reset.

    The cost is that these commands cannot run unattended. That cost is paid by
    :func:`cmd_deposit`, which needs no passphrase at all.
    """
    if not sys.stdin.isatty():
        raise Problem(
            "this needs the vault's passphrase, and the only way to give it is "
            "at a prompt — there is deliberately no argument, environment "
            "variable or file for it. For an unattended job use 'quenchkey "
            "deposit', which locks files into your own vault with the vault "
            "shut and no passphrase anywhere. See 'quenchkey help'.", USAGE)

    import getpass

    first = getpass.getpass(prompt)
    if not first:
        raise Problem("no passphrase entered", USAGE)
    if confirm and getpass.getpass("Again: ") != first:
        raise Problem("the two entries did not match", USAGE)
    return first


def _from_file(path: str) -> str:
    try:
        mode = os.stat(path).st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            print(f"warning: {path} is readable by others on this machine "
                  f"(mode {stat.S_IMODE(mode):04o}). chmod 600 it.",
                  file=sys.stderr)
        with open(path) as fh:
            passphrase = fh.read().split("\n")[0].strip()
    except OSError as exc:
        raise Problem(f"could not read {path}: {exc}", USAGE) from exc
    if not passphrase:
        raise Problem(f"{path} is empty", USAGE)
    return passphrase


# --------------------------------------------------------------------------
# opening the vault
# --------------------------------------------------------------------------

def open_vault(args, need_passphrase: bool = True):
    from .crypto import AuthenticationError
    from .vault import (
        ClockRollback, Vault, VaultLocked, VaultNotFound,
    )

    path = os.path.abspath(args.vault)
    if not os.path.exists(path):
        raise Problem(
            f"no vault at {path}. Create one in the application first: there "
            f"is no vault-creation command here on purpose, because choosing "
            f"a passphrase you cannot reset is not a thing to do in a "
            f"one-liner.", LOCKED)
    if not need_passphrase:
        return path

    passphrase = read_passphrase(args, f"Passphrase for {os.path.basename(path)}: ")
    try:
        return Vault.unlock(path, passphrase,
                            keyfile_path=getattr(args, "keyfile", None),
                            accept_clock_rollback=getattr(args, "accept_clock_rollback",
                                                          False))
    except AuthenticationError as exc:
        raise Problem(
            "wrong passphrase, wrong keyfile, or the vault has been "
            "altered — there is no way to tell those apart", LOCKED) from exc
    except ClockRollback as exc:
        raise Problem(
            f"this machine's clock is {int(exc.delta)}s behind the last time "
            f"the vault was opened. A deadline may have passed while it read "
            f"as though it had not. Pass --accept-clock-rollback if you know "
            f"why, and it will be recorded in the event log.", LOCKED) from exc
    except (VaultLocked, VaultNotFound) as exc:
        raise Problem(str(exc), LOCKED) from exc


#: Set once, in main(), when --json was asked for. Prose is then suppressed
#: so that standard output is a single JSON document and nothing else — a
#: caller piping this into jq should not have to strip a paragraph first.
_MACHINE_READABLE = False


def _out(text: str = "") -> None:
    if not _MACHINE_READABLE:
        print(text)


def _emit(payload, args) -> None:
    """The result as JSON, when that is what was asked for."""
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, default=str))


# --------------------------------------------------------------------------
# lock
# --------------------------------------------------------------------------

def cmd_lock(args) -> int:
    from . import expiry as expiry_mod, locker

    paths = [os.path.abspath(p) for p in args.files]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        raise Problem("not there: " + ", ".join(missing), USAGE)

    expires = parse_when(args.expires) if args.expires else None
    heartbeat = parse_duration(args.check_in) if args.check_in else None
    heartbeat_days = None if heartbeat is None else heartbeat / 86400.0

    if args.dry_run:
        _out("Would lock:")
        for path in paths:
            _out(f"  {path}")
        _out()
        _out("  deadline:  " + (expiry_mod.format_time(expires) if expires
                                else "none"))
        _out(f"  openings:  {args.max_opens if args.max_opens else 'unlimited'}")
        _out("  check in:  " + (f"every {heartbeat_days:g} days" if heartbeat_days
                                else "not required"))
        _out("  originals: " + ("shredded" if args.shred else "left alone"))
        _emit({"dry_run": True, "files": paths, "expires": expires,
               "max_opens": args.max_opens, "heartbeat_days": heartbeat_days},
              args)
        return OK

    vault = open_vault(args)
    try:
        result = locker.lock_files(
            vault, paths, expires,
            output_dir=args.output_dir or None,
            label=args.label or "",
            delete_originals=args.shred,
            delete_blob_on_expiry=args.delete_on_expiry,
            max_opens=args.max_opens,
            heartbeat_days=heartbeat_days,
            progress=_progress(args))
    finally:
        pass

    entry = result.entry
    _out(f"Locked {result.member_count} file"
         f"{'s' if result.member_count != 1 else ''} into "
         f"{term.name(result.blob_path)}")
    _out(f"  entry:    {entry.id}")
    _out(f"  rules:    {entry.rule_summary()}")
    if expires:
        _out(f"  key dies: {expiry_mod.format_time(expires)}")
    if args.shred:
        _out("  " + term.gone("The originals have been shredded. This is not "
                              "recoverable."))
    if entry.expires is None and entry.max_opens is None and heartbeat_days is None:
        _out("  " + term.decide_this(
            "No rules were set, so nothing will ever destroy this key on its "
            "own."))
    _emit({"entry": entry.id, "blob": result.blob_path,
           "files": result.member_count, "expires": entry.expires,
           "max_opens": entry.max_opens, "heartbeat_days": entry.heartbeat_days,
           "rules": entry.rule_summary()}, args)
    vault.lock()
    return OK


def _progress(args):
    # Silent unless somebody is watching. A progress line redrawing itself
    # with carriage returns is useful on a terminal and noise in a log file,
    # so a cron job gets no progress without having to ask for none.
    if getattr(args, "quiet", False) or getattr(args, "json", False):
        return None
    if not sys.stderr.isatty():
        return None
    last = {"line": ""}

    def report(stage: str, fraction: float) -> None:
        line = f"  {stage} {int(fraction * 100):3d}%"
        if line != last["line"]:
            print(line, end="\r", file=sys.stderr, flush=True)
            last["line"] = line
        if fraction >= 1.0:
            print(" " * len(line), end="\r", file=sys.stderr, flush=True)

    return report


# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------

def cmd_ls(args) -> int:
    from . import expiry as expiry_mod

    vault = open_vault(args)
    now = vault.effective_now()
    entries = vault.entries()
    if args.live_only:
        entries = [e for e in entries if not e.key_destroyed]

    if args.json:
        _emit([{
            "id": e.id,
            "name": e.display_name,
            "rules": e.rule_summary(),
            "expires": e.expires,
            "remaining": e.seconds_remaining(now),
            "opens": [e.open_count, e.max_opens],
            "destroyed": e.key_destroyed,
            "blob": e.blob_path,
            "size": e.plaintext_size,
        } for e in entries], args)
        vault.lock()
        return OK

    if not entries:
        _out("Nothing in this vault.")
        vault.lock()
        return OK

    width = max(len(e.display_name) for e in entries)
    for entry in entries:
        if entry.key_destroyed:
            state = term.gone("key destroyed".rjust(16))
        elif entry.deadline() is None:
            state = term.decide_this("no deadline".rjust(16))
        else:
            state = expiry_mod.format_remaining(entry, now).rjust(16)
        _out(f"{term.faint(entry.id[:8])}  {entry.display_name:<{width}}  "
             f"{state}  {entry.rule_summary()}")
    _out()
    live = [e for e in entries if not e.key_destroyed]
    _out(f"{len(live)} live, {len(entries) - len(live)} with the key destroyed. "
         f"Anchor {vault.chain_fingerprint}.")
    vault.lock()
    return OK


def cmd_status(args) -> int:
    from . import audit, expiry as expiry_mod, integrity, warnings as warnings_mod

    vault = open_vault(args)
    now = vault.effective_now()
    entries = vault.entries()
    live = [e for e in entries if not e.key_destroyed]
    due = expiry_mod.due_entries(vault, now)
    coming = warnings_mod.pending(vault, now)
    last_check = integrity.last_check(vault)
    report = vault.chain_report()

    if args.json:
        _emit({
            "vault": vault.path,
            "vault_id": vault.vault_id,
            "anchor": vault.chain_fingerprint,
            "chain_ok": report.ok,
            "entries": len(entries),
            "live": len(live),
            "destroyed": len(entries) - len(live),
            "due_now": [e.id for e in due],
            "warnings": [{"entry": w.entry_id, "level": w.level,
                          "seconds_left": w.seconds_left} for w in coming.due],
            "last_integrity_check": last_check,
            "audit_record": audit.is_armed(vault),
        }, args)
        vault.lock()
        return OK

    _out(f"Vault   {vault.path}")
    _out(f"        {vault.vault_id}")
    _out(f"Anchor  {term.name(vault.chain_fingerprint)}  "
         + (term.done("(chain verifies)") if report.ok
            else term.gone(f"({report.summary()})")))
    _out(f"Entries {len(entries)} — {len(live)} live, "
         f"{len(entries) - len(live)} with the key destroyed")
    if due:
        _out("Due now " + term.gone(
            f"{len(due)} — run 'quenchkey sweep' to destroy their keys"))
    if coming.due:
        _out("Coming  " + term.decide_this(coming.summary()))
    _out("Checked " + (f"{expiry_mod.format_time(last_check['at'])}, "
                       f"{last_check['intact']}/{last_check['checked']} intact"
                       if last_check else "never — run 'quenchkey check'"))
    _out("Auditor " + ("a record is published beside the vault"
                       if audit.is_armed(vault) else "no record published"))
    vault.lock()
    return CHECK_FAILED if (due or not report.ok) else OK


def cmd_open(args) -> int:
    from . import locker
    from .vault import KeyDestroyed

    vault = open_vault(args)
    entry = _find(vault, args.entry)
    destination = os.path.abspath(args.output_dir or os.getcwd())

    try:
        if args.loan:
            minutes = int((parse_duration(args.loan) or 1800) / 60)
            written = locker.check_out(vault, entry.id, destination, minutes,
                                       progress=_progress(args))
            _out(f"Lent out {len(written)} file"
                 f"{'s' if len(written) != 1 else ''} for {minutes} minutes:")
        else:
            written = locker.unlock_entry(vault, entry.id, destination,
                                          progress=_progress(args))
            _out(f"Extracted {len(written)} file"
                 f"{'s' if len(written) != 1 else ''}:")
    except KeyDestroyed as exc:
        raise Problem(f"{exc}. The locked file may still be on disk, and it "
                      f"is permanently unreadable.", CHECK_FAILED) from exc

    for path in written:
        _out(f"  {path}")
    after = vault.get(entry.id)
    if args.loan:
        _out("  Edits are locked back in when it comes back. Copies you make "
             "elsewhere are not reached.")
    else:
        _out("  " + term.decide_this("These are ordinary files now. Expiry "
                                        "cannot reach them."))
    if after.max_opens is not None:
        _out(f"  {after.open_count}/{after.max_opens} openings used")
    if after.key_destroyed:
        _out("  " + term.gone("That was the last opening, so the key has been "
                              "destroyed."))
    _emit({"entry": entry.id, "written": written,
           "opens": [after.open_count, after.max_opens],
           "destroyed": after.key_destroyed}, args)
    vault.lock()
    return OK


def cmd_checkin(args) -> int:
    from . import locker

    vault = open_vault(args)
    if args.entry:
        reports = [locker.check_in(vault, _find(vault, args.entry).id,
                                   save_edits=not args.discard_edits)]
    else:
        reports = locker.sweep_checkouts(vault)
        if not reports:
            _out("Nothing is out on loan past its time.")
            vault.lock()
            return OK

    for report in reports:
        _out(f"{report.entry_id[:8]}  {report.summary()}")
    stranded = [r for r in reports if r.edited and not r.saved]
    _emit([{"entry": r.entry_id, "edited": len(r.edited), "saved": r.saved,
            "shredded": len(r.shredded)} for r in reports], args)
    vault.lock()
    return CHECK_FAILED if stranded else OK


# --------------------------------------------------------------------------
# destroying
# --------------------------------------------------------------------------

def cmd_sweep(args) -> int:
    from . import expiry as expiry_mod, locker

    vault = open_vault(args)
    due = expiry_mod.due_entries(vault)
    if args.dry_run:
        if not due:
            _out("Nothing is due.")
        else:
            _out(f"{len(due)} would have their keys destroyed:")
            for entry in due:
                _out(f"  {entry.id[:8]}  {entry.display_name}  "
                     f"({entry.due_reason(vault.effective_now())})")
        _emit({"dry_run": True, "due": [e.id for e in due]}, args)
        vault.lock()
        return OK

    report = expiry_mod.sweep(vault, delete_blobs=not args.keep_files)
    locker.sweep_checkouts(vault)
    if report.expired:
        expiry_mod.check_in(vault)
    _out(report.summary())
    for path in report.blobs_deleted:
        _out(f"  deleted {path}")
    _emit({"expired": [e.id for e in report.expired],
           "deleted": report.blobs_deleted}, args)
    vault.lock()
    return OK


def cmd_expire(args) -> int:
    from . import expiry as expiry_mod

    vault = open_vault(args)
    entries = [_find(vault, name) for name in args.entries]
    live = [e for e in entries if not e.key_destroyed]
    if not live:
        _out("Those keys are already destroyed.")
        vault.lock()
        return OK

    _out("About to destroy the keys for:")
    for entry in live:
        _out(f"  {entry.id[:8]}  {entry.display_name}")
    _out()
    _out(term.gone(
        "This cannot be undone. Every copy of those locked files becomes "
        "permanently unreadable, everywhere, including copies you have "
        "forgotten about.") + " Files already extracted are not affected.")
    if not args.yes:
        raise Problem("refusing to do that without --yes", USAGE)

    report = expiry_mod.expire_now(vault, [e.id for e in live],
                                   delete_blobs=args.delete_files)
    _out(term.gone(f"Destroyed {len(report.expired)} key"
                    f"{'s' if len(report.expired) != 1 else ''}."))
    for entry in report.expired:
        _out(f"  {entry.id[:8]}  {entry.display_name}")
    _emit({"destroyed": [e.id for e in report.expired]}, args)
    vault.lock()
    return OK


# --------------------------------------------------------------------------
# checking
# --------------------------------------------------------------------------

def cmd_check(args) -> int:
    from . import integrity

    vault = open_vault(args)
    report = integrity.check(vault, progress=_progress(args))
    _out(report.summary())
    for finding in report.findings:
        if finding.ok and not args.verbose:
            continue
        painted = (finding.state.ljust(13) if finding.ok
                   else term.gone(finding.state.ljust(13))
                   if finding.state == "changed"
                   else term.decide_this(finding.state.ljust(13)))
        _out(f"  {painted} {finding.name}")
        if not finding.ok:
            _out(f"                {finding.explain()}")
    if report.advice():
        _out()
        _out(report.advice())

    if args.find and report.missing:
        found = integrity.search(vault, args.find)
        _out()
        _out(found.summary())
        if found.matches and args.relink:
            moved = integrity.relink(vault, found.matches)
            _out(f"Pointed {moved} entr{'ies' if moved != 1 else 'y'} at "
                 f"where the files actually are.")
            report = integrity.check(vault)
            _out(report.summary())
        elif found.matches:
            for match in found.matches:
                _out(f"  {match.describe()}")
            _out("Pass --relink to point the vault at them.")

    _emit({"ok": report.ok,
           "intact": [f.entry_id for f in report.intact],
           "changed": [f.entry_id for f in report.changed],
           "missing": [f.entry_id for f in report.missing]}, args)
    vault.lock()
    return OK if report.ok else CHECK_FAILED


def cmd_audit(args) -> int:
    from . import audit

    vault = open_vault(args)
    if args.stop:
        audit.disarm(vault)
        _out("Stopped publishing. Any copy an auditor already has goes on "
             "working with the passphrase you gave them.")
        vault.lock()
        return OK

    record_passphrase = _second_passphrase(
        args, "Passphrase for the audit record: ")
    if audit.is_armed(vault):
        written = audit.write(vault, record_passphrase)
    else:
        written = audit.arm(vault, record_passphrase)
    record = audit.build(vault)
    _out(f"Wrote {written}")
    _out(f"  {record.summary()}")
    _out("  There is no file key in it. Give an auditor that file and that "
         "passphrase, and nothing else.")
    _emit({"written": written, "entries": len(record.entries),
           "destroyed": len(record.destroyed)}, args)
    vault.lock()
    return OK


def _second_passphrase(args, prompt: str) -> str:
    """A passphrase that is not the vault's, and so not held to the same rule.

    An audit record opens metadata and no documents; a shared file opens that
    one file. Leaking either costs something real and bounded, where leaking
    the vault's costs everything in it forever — so these may come from the
    environment or a file, and a nightly compliance job can write an audit
    record with nobody present.
    """
    path = getattr(args, "record_passphrase_file", None)
    if path:
        return _from_file(path)
    from_environment = os.environ.get(RECORD_PASSPHRASE_VARIABLE)
    if from_environment:
        return from_environment
    if not sys.stdin.isatty():
        raise Problem(
            f"no passphrase available for the record. Set "
            f"{RECORD_PASSPHRASE_VARIABLE} or pass --record-passphrase-file. "
            "It must not be the vault's: that would hand an auditor every "
            "document.", USAGE)
    import getpass
    entered = getpass.getpass(prompt)
    if not entered:
        raise Problem("no passphrase entered", USAGE)
    return entered


def cmd_stamp(args) -> int:
    from . import timestamping

    vault = open_vault(args)
    report = timestamping.stamp_anchor(
        vault, args.authority, ca_file=args.certificate,
        output_path=args.output or None, timeout=args.timeout)
    _out(report.summary())
    if report.written:
        _out(f"  token at {report.written}")
    _emit({"ok": report.ok,
           "stamped": report.token.stamped if report.token else None,
           "verified": report.token.verified if report.token else False,
           "clock_corrected": report.clock_corrected,
           "written": report.written}, args)
    vault.lock()
    return OK if report.ok else FAILED


# --------------------------------------------------------------------------
# sharing and handing over
# --------------------------------------------------------------------------

def cmd_share(args) -> int:
    from . import locker

    paths = [os.path.abspath(p) for p in args.files]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        raise Problem("not there: " + ", ".join(missing), USAGE)

    passphrase = _second_passphrase(args, "Passphrase for the shared file: ")
    result = locker.lock_to_share(
        paths, passphrase,
        output_path=args.output or None,
        output_dir=args.output_dir or None,
        delete_originals=args.shred,
        progress=_progress(args))
    _out(f"Wrote {result.path}")
    _out(f"  {len(result.names)} file{'s' if len(result.names) != 1 else ''}, "
         f"opens with that passphrase on any machine, with no vault")
    _out("  " + term.decide_this(
        "It has no deadline and cannot be given one: the key travels inside "
        "the file, so there is nothing left anywhere to destroy.")
        + " Use 'quenchkey hand-over' if the other person runs Quenchkey and "
          "you want a deadline that holds.")
    _emit({"path": result.path, "files": len(result.names),
           "sha256": result.sha256}, args)
    return OK


def cmd_hand_over(args) -> int:
    from . import expiry as expiry_mod, handover

    paths = [os.path.abspath(p) for p in args.files]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        raise Problem("not there: " + ", ".join(missing), USAGE)

    try:
        card = handover.read_card(args.to)
    except handover.HandoverError as exc:
        raise Problem(str(exc), USAGE) from exc

    expires = parse_when(args.expires) if args.expires else None
    heartbeat = parse_duration(args.check_in) if args.check_in else None

    sender = None if args.anonymous else open_vault(args)
    written = handover.lock_for(
        paths, card,
        expires=expires,
        max_opens=args.max_opens,
        heartbeat_days=None if heartbeat is None else heartbeat / 86400.0,
        output_path=args.output or None,
        output_dir=args.output_dir or None,
        note=args.note or "",
        sender=sender,
        delete_originals=args.shred,
        progress=_progress(args))

    _out(f"Wrote {written}")
    _out(f"  addressed to vault {card.vault_id[:16]} "
         f"({card.label or 'unnamed'}), fingerprint {card.fingerprint}")
    _out("  terms: " + (expiry_mod.format_time(expires) if expires
                        else "no deadline")
         + (f", {args.max_opens} openings" if args.max_opens else ""))
    _out("  Nobody can read it until they accept it — including you. When "
         "they do, the deadline lands in their vault and their own sweep "
         "enforces it. " + term.decide_this(
             "They can decline, and nothing reaches a copy they have already "
             "extracted."))
    if sender is not None:
        sender.lock()
    _emit({"path": written, "to": card.vault_id, "expires": expires}, args)
    return OK


def cmd_deposit(args) -> int:
    """Lock files into your own vault without opening it.

    The one command here that needs no passphrase anywhere, which makes it the
    right one for an unattended job. It is a handover addressed to yourself:
    the file key is wrapped to your own vault's public identity, so the file is
    unreadable the moment it is written — by anybody, including the script that
    wrote it and the person who set the script up.

    You accept them next time you open the vault, on the terms the script
    proposed. Nothing on the machine ever had to hold your passphrase, which
    is the whole point of doing it this way rather than putting one in a cron
    environment.
    """
    from . import expiry as expiry_mod, handover

    paths = [os.path.abspath(p) for p in args.files]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        raise Problem("not there: " + ", ".join(missing), USAGE)

    try:
        card = handover.read_card(args.to)
    except handover.HandoverError as exc:
        raise Problem(str(exc), USAGE) from exc

    expires = parse_when(args.expires) if args.expires else None
    heartbeat = parse_duration(args.check_in) if args.check_in else None

    written = handover.lock_for(
        paths, card,
        expires=expires,
        max_opens=args.max_opens,
        heartbeat_days=None if heartbeat is None else heartbeat / 86400.0,
        output_path=args.output or None,
        output_dir=args.output_dir or None,
        note=args.note or "",
        sender=None,
        delete_originals=args.shred,
        progress=_progress(args))

    _out(f"Deposited {len(paths)} file{'s' if len(paths) != 1 else ''} into "
         f"{term.name(os.path.basename(written))}")
    _out(f"  for vault {card.vault_id[:16]} ({card.label or 'unnamed'})")
    _out("  terms: " + (expiry_mod.format_time(expires) if expires
                        else "no deadline")
         + (f", {args.max_opens} openings" if args.max_opens else ""))
    _out("  " + term.done("No passphrase was needed, and none was used."))
    _out("  It is unreadable until that vault accepts it — including by this "
         "script and by you, until you next open the vault.")
    if args.shred:
        _out("  " + term.gone("The originals have been shredded. Nothing can "
                              "undo that, and the deposit is now the only "
                              "copy."))
    _emit({"path": written, "for": card.vault_id, "files": len(paths),
           "expires": expires, "passphrase_used": False}, args)
    return OK


def cmd_accept(args) -> int:
    from . import handover

    vault = open_vault(args)
    try:
        described = handover.describe(args.file)
    except handover.HandoverError as exc:
        raise Problem(str(exc), USAGE) from exc

    terms = described["terms"]
    who = terms.sender_label or terms.sender_vault_id[:16] or "somebody unidentified"
    _out(f"From {who}")
    _out(f"  files: {', '.join(terms.names) or '(none recorded)'}")
    _out(f"  terms: {terms.describe()}")
    if terms.note:
        _out(f"  note:  {terms.note}")

    if args.describe_only:
        _emit({"terms": terms.to_dict(), "for_me":
               handover.addressed_to_me(vault, args.file)}, args)
        vault.lock()
        return OK

    if not args.yes:
        raise Problem(
            "accepting puts this key in your vault on those terms, and there "
            "is no way to read the file without accepting them. Pass --yes.",
            USAGE)

    entry = handover.accept(vault, args.file)
    _out(f"Accepted. {entry.display_name} is an ordinary entry now: "
         f"{entry.rule_summary()}, enforced by this vault.")
    _emit({"entry": entry.id, "rules": entry.rule_summary()}, args)
    vault.lock()
    return OK


def cmd_card(args) -> int:
    from . import handover

    vault = open_vault(args)
    card = handover.my_card(vault, label=args.label or vault.custodian.name or "")
    if args.output:
        written = handover.write_card(card, args.output)
        _out(f"Wrote {written}")
    _out(f"  vault       {card.vault_id}")
    _out(f"  fingerprint {card.fingerprint}")
    _out("  It holds no secret — safe to email, paste or publish. The worst "
         "somebody can do with it is send you a file only you can open.")
    _emit(card.to_dict(), args)
    vault.lock()
    return OK


# --------------------------------------------------------------------------
# odds and ends
# --------------------------------------------------------------------------

def cmd_backup(args) -> int:
    from . import backup

    vault = open_vault(args)
    info = backup.create(vault, args.destination)
    _out(f"Wrote {info.path}")
    _out(f"  {info.entries} entr{'ies' if info.entries != 1 else 'y'}, "
         f"{info.live_entries} live, chain of {info.chain_length}")
    _out("  Keep it somewhere the vault is not. Restoring one brings back "
         "keys destroyed since it was taken, which is why restoring is done "
         "in the application where the cost is stated first.")
    _emit({"path": info.path, "entries": info.entries,
           "live": info.live_entries}, args)
    vault.lock()
    return OK


def cmd_warn(args) -> int:
    from . import warnings as warnings_mod

    vault = open_vault(args)
    if args.send:
        report = warnings_mod.send(vault, _terminal_notifier)
    else:
        report = warnings_mod.pending(vault)
        for warning in report.due:
            _out(f"{warning.level:<6} {warning.title()}")
            _out(f"       {warning.message()}")
    if not report.due:
        _out(report.summary())
    _emit([{"entry": w.entry_id, "level": w.level, "name": w.name,
            "seconds_left": w.seconds_left} for w in report.due], args)
    vault.lock()
    # Two different questions, two different answers. Plain `warn` is asking
    # "is anything coming?", so something coming is the 4 that a monitoring
    # job watches for. `warn --send` is asking "deliver the warnings", and
    # that succeeded — a script running it in cron should not be told the
    # delivery failed just because there was something to deliver.
    if args.send:
        return OK
    return CHECK_FAILED if report.due else OK


def _terminal_notifier(title: str, message: str, urgency: str) -> None:
    print(f"[{urgency}] {title}: {message}")


def _find(vault, needle: str):
    """An entry by id, id prefix, or name. Ambiguity is an error, not a guess."""
    entries = vault.entries()
    exact = [e for e in entries if e.id == needle]
    if exact:
        return exact[0]
    matches = [e for e in entries
               if e.id.startswith(needle.lower()) or e.display_name == needle]
    if not matches:
        loose = [e for e in entries if needle.lower() in e.display_name.lower()]
        matches = loose
    if not matches:
        raise Problem(f"nothing in this vault matches '{needle}'. "
                      f"'quenchkey ls' lists them.", USAGE)
    if len(matches) > 1:
        names = ", ".join(f"{e.id[:8]} ({e.display_name})" for e in matches[:5])
        raise Problem(f"'{needle}' matches {len(matches)} entries: {names}. "
                      f"Use more of the id.", USAGE)
    return matches[0]


# --------------------------------------------------------------------------
# the overview, grouped by what somebody is trying to do
# --------------------------------------------------------------------------

def cmd_help(args) -> int:
    """One page, arranged by task rather than alphabetically.

    ``--help`` lists commands in the order the parser happens to hold them,
    which is the right answer to "what are the flags for lock" and the wrong
    one to "how do I use this". This is the second question.
    """
    from . import __version__

    c = term
    out = []
    add = out.append

    add("")
    add(f"  {c.heading('Quenchkey ' + __version__)}  {c.faint('· the key goes out')}")
    add("")
    add("  Files whose keys expire. The encrypted file and its key live in")
    add("  different places, so destroying the key makes every copy of the")
    add("  file unreadable at once — wherever those copies are.")
    add("")
    add(c.rule())

    groups = [
        ("Locking things up", [
            ("lock FILE...",
             "lock into the vault, with rules",
             "quenchkey lock report.pdf --expires 90d"),
            ("deposit FILE... --to CARD",
             "lock into your own vault with no passphrase at all",
             "quenchkey deposit exports/*.csv --to mine.qkid --expires 90d"),
            ("share FILE...",
             "lock with a passphrase of its own, for anybody",
             "quenchkey share notes.txt"),
            ("hand-over FILE... --to CARD",
             "send to another vault, deadline and all",
             "quenchkey hand-over draft.docx --to bob.qkid --expires 14d"),
        ]),
        ("Looking at what is there", [
            ("ls", "every entry, with its rules and time remaining", None),
            ("status", "one screen; exits 4 if something wants attention", None),
            ("warn", "what is about to have its key destroyed", None),
            ("check", "read every locked file back and compare its digest", None),
        ]),
        ("Getting things out", [
            ("open ENTRY", "extract it", "quenchkey open report"),
            ("open ENTRY --loan 4h",
             "borrow it; edits are locked back in when it returns", None),
            ("check-in [ENTRY]", "bring a loan back, keeping any edits", None),
            ("accept FILE --yes", "take a handover into this vault", None),
        ]),
        ("Destroying keys", [
            ("sweep", "everything past its deadline", None),
            ("expire ENTRY --yes", "one, now, ahead of its deadline", None),
        ]),
        ("Proving things to other people", [
            ("card --output PATH", "this vault's identity card; holds no secret", None),
            ("audit", "a record an auditor can read, with no keys in it", None),
            ("stamp", "have an authority sign the anchor", None),
            ("backup PATH", "a copy, somewhere the vault is not", None),
        ]),
    ]

    for title, rows in groups:
        add("")
        add(f"  {c.heading(title)}")
        for command, what, example in rows:
            add(f"    {c.name(command.ljust(30))} {what}")
            if example:
                add(f"    {' ' * 30} {c.faint(example)}")

    add("")
    add(c.rule())
    add("")
    add(f"  {c.heading('Lengths of time')}")
    for flag, what in (
            ("--expires",
             "90d  ·  6h  ·  2 weeks  ·  1.5h  ·  1y  ·  2027-01-01  ·  never"),
            ("--check-in",
             "a dead man's switch: destroyed if the vault is not opened this often"),
            ("--max-opens", "destroyed after this many openings")):
        add(f"    {c.name(flag.ljust(14))} {what}")
    add("")
    add(f"  {c.heading('The passphrase')}")
    add(f"    {c.done('It comes from a prompt, and from nowhere else.')}")
    add("    No argument, because arguments are visible to every process and")
    add("    land in shell history. No environment variable, because it is")
    add("    inherited by every child and ends up in systemd units and CI")
    add("    logs. No file, because a file holding a vault's passphrase is")
    add("    the one thing this tool tells you not to make.")
    add("")
    add(f"    So these commands {c.decide_this('cannot run unattended')} "
        f"— which is the point.")
    add(f"    A cron job does not need them: {c.name('deposit')} locks files "
        f"into your")
    add("    own vault using only your identity card, which holds no secret,")
    add("    with the vault shut and no passphrase anywhere. You accept them")
    add("    next time you open the vault.")
    add("")
    add(f"  {c.heading('Exit codes')}")
    add(f"    {c.done('0')}  it happened        "
        f"{c.name('2')}  the command line was wrong")
    add(f"    {c.name('1')}  it did not         "
        f"{c.name('3')}  the vault would not open")
    add(f"    {c.decide_this('4')}  a check failed: something expired, altered or missing")
    add("")
    add("  " + c.faint("quenchkey COMMAND --help for one command  ·  "
                        "quenchkey on its own opens the window"))
    add("")

    print("\n".join(out))
    return OK


# --------------------------------------------------------------------------
# the parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    from .vault import DEFAULT_VAULT_PATH

    parser = argparse.ArgumentParser(
        prog="quenchkey",
        description="Lock files whose keys expire, from a terminal or a script.",
        epilog="The vault's passphrase comes from a prompt and nowhere else "
               "— no argument, no environment variable, no file. For an "
               "unattended job see 'quenchkey deposit'.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="store_true",
                        help="print the version and exit")

    # These work on either side of the subcommand, because both are natural
    # to type and being told off for guessing wrong is a poor greeting. The
    # copies on the subcommands suppress their defaults, so a value given
    # before the subcommand is not quietly overwritten by one after it.
    def shared(target, defaults: bool) -> None:
        nothing = argparse.SUPPRESS
        target.add_argument(
            "--vault", metavar="PATH",
            default=DEFAULT_VAULT_PATH if defaults else nothing,
            help=f"which vault (default: {DEFAULT_VAULT_PATH})")
        target.add_argument(
            "--keyfile", metavar="PATH", default=None if defaults else nothing,
            help="the second factor, if this vault has one")
        target.add_argument(
            "--accept-clock-rollback", action="store_true",
            default=False if defaults else nothing,
            help="open a vault whose watermark is ahead of this machine's "
                 "clock, recording that you did")
        target.add_argument("--json", action="store_true",
                            default=False if defaults else nothing,
                            help="machine-readable output")
        target.add_argument("--quiet", action="store_true",
                            default=False if defaults else nothing,
                            help="no progress on standard error")

    shared(parser, defaults=True)
    common = argparse.ArgumentParser(add_help=False)
    shared(common, defaults=False)

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # -- lock, the reason this exists
    lock = sub.add_parser(
        "lock", parents=[common],
        help="lock files into the vault, with rules",
        description="Lock files into the vault. The key stays in the vault; "
                    "the .qkey file can go anywhere. When the key is "
                    "destroyed every copy of that file becomes unreadable at "
                    "once, wherever it is.",
        epilog="Examples:\n"
               "  quenchkey lock report.pdf --expires 90d\n"
               "  quenchkey lock exports/*.csv --expires 2027-01-01 --shred\n"
               "  quenchkey lock notes.txt --max-opens 1 --delete-on-expiry\n"
               "  quenchkey lock ~/Archive --expires 1y --check-in 30d\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    lock.add_argument("files", nargs="+", metavar="FILE",
                      help="files or folders to lock")
    lock.add_argument("--expires", metavar="WHEN",
                      help="when the key is destroyed: a length of time "
                           "(90d, 6h, 2 weeks, 1y), an absolute date "
                           "(2027-01-01, or with a time), or 'never'")
    lock.add_argument("--max-opens", type=int, metavar="N",
                      help="destroy the key after N openings")
    lock.add_argument("--check-in", metavar="EVERY",
                      help="a dead man's switch: destroy the key if the vault "
                           "is not opened this often (30d, 6 months)")
    lock.add_argument("--shred", action="store_true",
                      help="shred the originals once they are locked. Not "
                           "recoverable")
    lock.add_argument("--delete-on-expiry", action="store_true",
                      help="also delete this machine's copy of the .qkey file "
                           "when the key is destroyed")
    lock.add_argument("--output-dir", metavar="DIR",
                      help="where to write the .qkey (default: beside the "
                           "first file)")
    lock.add_argument("--label", metavar="TEXT",
                      help="a name for this entry in the table")
    lock.add_argument("--dry-run", action="store_true",
                      help="say what would happen, touch nothing")
    lock.set_defaults(handler=cmd_lock)

    # -- reading
    listing = sub.add_parser("ls", parents=[common],
                             help="list what is in the vault")
    listing.add_argument("--live-only", action="store_true",
                         help="hide entries whose key is already destroyed")
    listing.set_defaults(handler=cmd_ls)

    status = sub.add_parser(
        "status", parents=[common],
        help="one screen: entries, deadlines, warnings, last check",
        description="Exits 4 if something is due or the chain does not "
                    "verify, so a monitoring job can watch a vault.")
    status.set_defaults(handler=cmd_status)

    opening = sub.add_parser("open", parents=[common],
                             help="extract an entry")
    opening.add_argument("entry", help="an entry id, an id prefix, or a name")
    opening.add_argument("--output-dir", metavar="DIR",
                         help="where the files go (default: here)")
    opening.add_argument("--loan", metavar="FOR",
                         help="open on loan for this long (30m, 4h), so edits "
                              "are locked back in and the copies cleared away")
    opening.set_defaults(handler=cmd_open)

    checkin = sub.add_parser("check-in", parents=[common],
                             help="bring a loan back, keeping any edits")
    checkin.add_argument("entry", nargs="?",
                         help="which one; omit for everything overdue")
    checkin.add_argument("--discard-edits", action="store_true",
                         help="throw the changes away on purpose. Without "
                              "this, edits are locked back into the vault")
    checkin.set_defaults(handler=cmd_checkin)

    # -- destroying
    sweep = sub.add_parser(
        "sweep", parents=[common],
        help="destroy the keys of everything past its deadline",
        description="What the background timer does, on demand.")
    sweep.add_argument("--dry-run", action="store_true",
                       help="list what is due, destroy nothing")
    sweep.add_argument("--keep-files", action="store_true",
                       help="do not delete .qkey files even where the entry "
                            "asked for it")
    sweep.set_defaults(handler=cmd_sweep)

    expire = sub.add_parser(
        "expire", parents=[common],
        help="destroy a key now, ahead of its deadline",
        description="Irreversible. Every copy of that locked file becomes "
                    "permanently unreadable, everywhere.")
    expire.add_argument("entries", nargs="+", metavar="ENTRY")
    expire.add_argument("--yes", action="store_true",
                        help="required: this cannot be undone")
    expire.add_argument("--delete-files", action="store_true",
                        help="also delete this machine's .qkey copies")
    expire.set_defaults(handler=cmd_expire)

    # -- checking
    check = sub.add_parser(
        "check", parents=[common],
        help="verify every locked file still matches its recorded digest",
        description="Exits 4 if anything is altered or missing.")
    check.add_argument("--verbose", action="store_true",
                       help="list intact files too")
    check.add_argument("--find", metavar="DIR",
                       help="search this folder for missing files, matching "
                            "on the digest rather than the name")
    check.add_argument("--relink", action="store_true",
                       help="with --find, point the vault at what was found")
    check.set_defaults(handler=cmd_check)

    warn = sub.add_parser(
        "warn", parents=[common],
        help="what is about to have its key destroyed",
        description="Exits 4 if anything is inside a warning window, so a "
                    "monitoring job can watch for it. With --send it exits 0 "
                    "on successful delivery instead, because then the "
                    "question being asked is a different one.")
    warn.add_argument("--send", action="store_true",
                      help="deliver the warnings and mark them as sent, so "
                           "they are not repeated. Exits 0 when delivery "
                           "worked, whether or not there was anything to "
                           "deliver. Without this, looking is free and "
                           "tomorrow's warning is not silenced")
    warn.set_defaults(handler=cmd_warn)

    audit_cmd = sub.add_parser(
        "audit", parents=[common],
        help="publish a record an auditor can check, with no keys in it")
    audit_cmd.add_argument("--record-passphrase-file", metavar="PATH",
                           help="the record's own passphrase, which must not "
                                "be the vault's")
    audit_cmd.add_argument("--stop", action="store_true",
                           help="stop publishing and delete the record")
    audit_cmd.set_defaults(handler=cmd_audit)

    stamp = sub.add_parser(
        "stamp", parents=[common],
        help="have a timestamp authority sign this vault's anchor")
    stamp.add_argument("--authority", default="http://timestamp.digicert.com",
                       metavar="URL", help="default: %(default)s")
    stamp.add_argument("--certificate", metavar="PATH",
                       help="the authority's certificate, so the token is "
                            "verified rather than merely stored")
    stamp.add_argument("--output", metavar="PATH", help="where to keep the token")
    stamp.add_argument("--timeout", type=float, default=20.0, metavar="SECONDS")
    stamp.set_defaults(handler=cmd_stamp)

    # -- sending
    share = sub.add_parser(
        "share", parents=[common],
        help="lock files with their own passphrase, for anybody",
        description="The file carries its own key, so it opens anywhere with "
                    "no vault — and can never expire.")
    share.add_argument("files", nargs="+", metavar="FILE")
    share.add_argument("--output", metavar="PATH")
    share.add_argument("--output-dir", metavar="DIR")
    share.add_argument("--record-passphrase-file", metavar="PATH",
                       dest="record_passphrase_file",
                       help="the shared file's own passphrase")
    share.add_argument("--shred", action="store_true",
                       help="shred the originals once they are locked")
    share.set_defaults(handler=cmd_share)

    hand = sub.add_parser(
        "hand-over", parents=[common],
        help="send files to another vault, deadline and all",
        description="Wraps the key to the recipient's vault, so when they "
                    "accept it the deadline lands there and their own sweep "
                    "enforces it.",
        epilog="Examples:\n"
               "  quenchkey hand-over draft.docx --to bob.qkid --expires 14d\n"
               "  quenchkey card --output mine.qkid     # to give somebody\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    hand.add_argument("files", nargs="+", metavar="FILE")
    hand.add_argument("--to", required=True, metavar="CARD",
                      help="their identity card (.qkid)")
    hand.add_argument("--expires", metavar="WHEN")
    hand.add_argument("--max-opens", type=int, metavar="N")
    hand.add_argument("--check-in", metavar="EVERY")
    hand.add_argument("--note", metavar="TEXT",
                      help="a line they see before accepting")
    hand.add_argument("--output", metavar="PATH")
    hand.add_argument("--output-dir", metavar="DIR")
    hand.add_argument("--shred", action="store_true")
    hand.add_argument("--anonymous", action="store_true",
                      help="do not record which vault sent it, and do not "
                           "open yours at all")
    hand.set_defaults(handler=cmd_hand_over)

    deposit = sub.add_parser(
        "deposit", parents=[common],
        help="lock into your own vault with no passphrase at all",
        description="A handover addressed to yourself. The file key is wrapped "
                    "to your own vault's public identity, so the file is "
                    "unreadable the moment it is written and no passphrase is "
                    "needed to write it. You accept them next time you open "
                    "the vault. This is the right command for a cron job: "
                    "nothing on the machine has to hold your passphrase.",
        epilog="First, once, from the application or `quenchkey card`:\n"
               "  quenchkey card --output ~/.config/quenchkey/mine.qkid\n"
               "\nThen, nightly, with no secret anywhere:\n"
               "  quenchkey deposit /srv/exports/*.csv \\\n"
               "      --to ~/.config/quenchkey/mine.qkid \\\n"
               "      --expires 90d --shred\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    deposit.add_argument("files", nargs="+", metavar="FILE")
    deposit.add_argument("--to", required=True, metavar="CARD",
                         help="your own identity card (.qkid), written once by "
                              "`quenchkey card --output`")
    deposit.add_argument("--expires", metavar="WHEN")
    deposit.add_argument("--max-opens", type=int, metavar="N")
    deposit.add_argument("--check-in", metavar="EVERY")
    deposit.add_argument("--note", metavar="TEXT",
                         help="a line you see before accepting")
    deposit.add_argument("--output", metavar="PATH")
    deposit.add_argument("--output-dir", metavar="DIR")
    deposit.add_argument("--shred", action="store_true",
                         help="shred the originals once deposited")
    deposit.set_defaults(handler=cmd_deposit)

    accept = sub.add_parser("accept", parents=[common],
                            help="take a handover into this vault")
    accept.add_argument("file", metavar="FILE")
    accept.add_argument("--yes", action="store_true",
                        help="required: accepting means taking the terms")
    accept.add_argument("--describe-only", action="store_true",
                        help="read the terms and stop")
    accept.set_defaults(handler=cmd_accept)

    card = sub.add_parser("card", parents=[common],
                          help="this vault's identity card, for handovers")
    card.add_argument("--output", metavar="PATH", help="where to write it")
    card.add_argument("--label", metavar="TEXT", help="a name on the card")
    card.set_defaults(handler=cmd_card)

    backup_cmd = sub.add_parser(
        "backup", parents=[common],
        help="copy the vault somewhere the vault is not")
    backup_cmd.add_argument("destination", metavar="PATH",
                            help="a file, or a folder to write into")
    backup_cmd.set_defaults(handler=cmd_backup)

    overview = sub.add_parser(
        "help", parents=[common],
        help="one page, arranged by what you are trying to do")
    overview.set_defaults(handler=cmd_help)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "version", False):
        from . import __version__
        print(f"Quenchkey {__version__}")
        return OK
    if not getattr(args, "handler", None):
        parser.print_help()
        return USAGE

    global _MACHINE_READABLE
    _MACHINE_READABLE = bool(getattr(args, "json", False))
    term.decide(machine_readable=_MACHINE_READABLE)

    try:
        return args.handler(args)
    except Problem as problem:
        print(f"quenchkey: {problem}", file=sys.stderr)
        return problem.code
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
        return FAILED
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        print(f"quenchkey: {type(exc).__name__}: {exc}", file=sys.stderr)
        return FAILED


if __name__ == "__main__":
    sys.exit(main())

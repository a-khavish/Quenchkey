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

"""Getting the time from somebody who is not you, and proving it later.

The weakest joint in local expiry is the clock. Everything in this tool is
honest about that: the vault keeps a watermark and never accepts a time
earlier than the latest it has seen, which makes a clock set backwards
*evident* rather than impossible. Somebody with your machine can still wind it
back before the vault has noticed the deadline pass.

A timestamp from an authority narrows that considerably, and the way it does
is worth being exact about, because it is easy to overclaim.

**What a token is.** An RFC 3161 timestamp authority takes a hash, and returns
that hash and a time, signed. It never sees the data. The token proves one
thing and proves it forever, offline, to anybody: *this hash existed no later
than this time*.

**What it buys here, in two places.**

1. *The anchor becomes third-party evidence.* The anchor already lets you
   publish a fingerprint of the vault's whole history somewhere you do not
   control. A token does the publishing for you: a signature from a party
   neither you nor an auditor controls, saying that history existed at that
   moment. Somebody who later restores an old backup of the vault cannot
   produce a token for the newer chain head, because they would need the
   authority to sign it with a date that has passed.

2. *The clock is corrected rather than trusted.* Fetching a token tells the
   vault what the time is according to somebody else. That reading advances
   the watermark, so a machine whose clock was wound back is put right the
   next time it can reach an authority — without the tool ever having to trust
   the local clock to be honest about having been wrong.

**What it does not buy, which matters more.**

* It does not work offline. A machine kept off the network keeps whatever
  protection the ratchet gives it and no more, and this module never pretends
  otherwise: a fetch that fails is reported as a fetch that failed, and the
  deadline is still enforced on the ratchet.
* It cannot stop the clock being wound back. It can only make the winding
  visible and correct it afterwards.
* It is only as good as the authority. A token verifies against a certificate
  you have to supply; without one, a token is stored but not verified, and
  this module says so rather than showing a green tick it has not earned.

**Why openssl.** The request is built here, because it is a small, fixed
structure and building it by hand is checkable. Verification is handed to
``openssl ts -verify``, because verifying a CMS signature chain is exactly the
kind of thing not to write yourself, and openssl is on every Linux desktop
this tool targets. Without it, tokens are fetched and stored but reported as
unverified.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

#: Authorities that answer an unauthenticated POST. None is the default: this
#: is off unless somebody turns it on, because it is the one feature here that
#: talks to the network at all.
KNOWN_AUTHORITIES: list[tuple[str, str]] = [
    ("DigiCert", "http://timestamp.digicert.com"),
    ("Sectigo", "http://timestamp.sectigo.com"),
    ("FreeTSA", "https://freetsa.org/tsr"),
    ("Apple", "http://timestamp.apple.com/ts01"),
]

CONTENT_TYPE = "application/timestamp-query"
REPLY_TYPE = "application/timestamp-reply"
TOKEN_SUFFIX = ".tsr"

#: Where the tokens this vault has collected are remembered.
NOTE_KEY = "timestamps"

DEFAULT_TIMEOUT = 20.0


class TimestampError(Exception):
    """A timestamp could not be fetched, read or verified."""


class Offline(TimestampError):
    """The authority could not be reached. Not a failure of the vault."""


# --------------------------------------------------------------------------
# building the request, by hand, because it is small enough to check
# --------------------------------------------------------------------------

def _der(tag: int, body: bytes) -> bytes:
    """One DER element: tag, length, contents."""
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def _integer(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return _der(0x02, raw)


#: OID 2.16.840.1.101.3.4.2.1 — SHA-256, as DER contents.
SHA256_OID = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])


def build_request(digest: bytes, nonce: Optional[int] = None,
                  request_certificate: bool = True) -> bytes:
    """A TimeStampReq for one SHA-256 digest.

    ::

        TimeStampReq ::= SEQUENCE {
            version       INTEGER { v1(1) },
            messageImprint MessageImprint,
            nonce         INTEGER OPTIONAL,
            certReq       BOOLEAN DEFAULT FALSE }

    The nonce is what ties the answer to this question: a reply carrying a
    different nonce is a replay of somebody else's, and is refused.
    """
    if len(digest) != 32:
        raise TimestampError("a SHA-256 digest is 32 bytes")
    algorithm = _der(0x30, _der(0x06, SHA256_OID) + _der(0x05, b""))
    imprint = _der(0x30, algorithm + _der(0x04, digest))

    body = _integer(1) + imprint
    if nonce is not None:
        body += _integer(nonce)
    if request_certificate:
        body += _der(0x01, b"\xff")
    return _der(0x30, body)


# --------------------------------------------------------------------------
# fetching one
# --------------------------------------------------------------------------

@dataclass
class Token:
    """A timestamp, and what is known about it."""

    digest: str
    authority: str
    raw: bytes = b""
    #: What the authority says the time was, as a Unix timestamp.
    stamped: float = 0.0
    #: Whether the signature was checked, and against what.
    verified: bool = False
    verified_against: str = ""
    #: What the token is about, in this tool's terms.
    covers: str = ""
    note: str = ""

    def describe(self) -> str:
        from . import expiry as expiry_mod
        when = expiry_mod.format_time(self.stamped) if self.stamped else "unknown"
        state = ("verified" if self.verified
                 else "stored but not verified — no certificate supplied")
        return f"{self.authority} · {when} · {state}"

    def to_dict(self) -> dict:
        return {
            "digest": self.digest,
            "authority": self.authority,
            "stamped": self.stamped,
            "verified": self.verified,
            "verified_against": self.verified_against,
            "covers": self.covers,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "Token":
        return cls(
            digest=str(raw.get("digest", "")),
            authority=str(raw.get("authority", "")),
            stamped=float(raw.get("stamped", 0.0)),
            verified=bool(raw.get("verified")),
            verified_against=str(raw.get("verified_against", "")),
            covers=str(raw.get("covers", "")),
            note=str(raw.get("note", "")),
        )


def fetch(digest: bytes, authority: str,
          timeout: float = DEFAULT_TIMEOUT,
          ca_file: Optional[str] = None,
          covers: str = "") -> Token:
    """Ask an authority to sign a hash and a time.

    The hash goes out; nothing else does. The authority learns that somebody
    asked about *some* 32-byte value, and that is the whole of what it learns.
    """
    nonce = int.from_bytes(os.urandom(8), "big") | 1
    request = build_request(digest, nonce=nonce)

    posted = urllib.request.Request(
        authority, data=request,
        headers={"Content-Type": CONTENT_TYPE, "Content-Length": str(len(request))})
    try:
        with urllib.request.urlopen(posted, timeout=timeout) as response:
            raw = response.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise Offline(
            f"could not reach {authority}: {exc}. The deadline is still "
            f"enforced on this machine's own watermark; what is missing is "
            f"the outside opinion of what time it is.") from exc

    if not raw:
        raise TimestampError(f"{authority} returned nothing")

    token = Token(digest=digest.hex(), authority=authority, raw=raw,
                  covers=covers)
    _read_reply(token, nonce)
    if ca_file:
        _verify(token, digest, ca_file)
    else:
        token.note = ("no certificate was supplied, so the signature on this "
                      "token has not been checked")
    return token


def _openssl() -> Optional[str]:
    return shutil.which("openssl")


def _read_reply(token: Token, nonce: Optional[int] = None) -> None:
    """Pull the time out of a reply, and check it answers our question."""
    binary = _openssl()
    if not binary:
        token.note = ("openssl is not installed, so the time inside this "
                      "token could not be read")
        return
    with tempfile.NamedTemporaryFile(suffix=TOKEN_SUFFIX, delete=False) as fh:
        fh.write(token.raw)
        path = fh.name
    try:
        result = subprocess.run([binary, "ts", "-reply", "-in", path, "-text"],
                                capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        token.note = f"could not read the reply: {exc}"
        return
    finally:
        os.unlink(path)

    if result.returncode != 0:
        raise TimestampError(
            f"{token.authority} did not return a timestamp: "
            f"{(result.stderr or result.stdout).strip()[:200]}")

    text = result.stdout
    if "Status: Granted" not in text:
        raise TimestampError(
            f"{token.authority} refused the request: "
            f"{_field(text, 'Status description') or 'no reason given'}")

    stamped = _field(text, "Time stamp")
    if stamped:
        token.stamped = _parse_time(stamped)

    # A reply carrying somebody else's nonce is a replay, not an answer.
    if nonce is not None:
        answered = _field(text, "Nonce")
        if answered:
            try:
                if int(answered, 16) != nonce:
                    raise TimestampError(
                        f"{token.authority} answered with a different nonce "
                        f"than was asked — this reply belongs to another "
                        f"request and has been discarded")
            except ValueError:
                pass


def _field(text: str, name: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(name + ":"):
            return stripped.split(":", 1)[1].strip()
    return ""


def _parse_time(value: str) -> float:
    """openssl prints e.g. ``Sep 30 15:51:00 2026 GMT``."""
    cleaned = value.split(".")[0].replace(" GMT", "").strip()
    for pattern in ("%b %d %H:%M:%S %Y", "%b  %d %H:%M:%S %Y"):
        try:
            import calendar
            return float(calendar.timegm(time.strptime(cleaned, pattern)))
        except ValueError:
            continue
    return 0.0


def _verify(token: Token, digest: bytes, ca_file: str) -> None:
    """Hand the signature to openssl, which is better at this than I am."""
    binary = _openssl()
    if not binary:
        token.note = ("openssl is not installed, so the signature could not "
                      "be checked")
        return
    if not os.path.exists(ca_file):
        token.note = f"no certificate at {ca_file}, so nothing was checked"
        return

    with tempfile.NamedTemporaryFile(suffix=TOKEN_SUFFIX, delete=False) as fh:
        fh.write(token.raw)
        reply = fh.name
    query = build_request(digest, nonce=None, request_certificate=True)
    with tempfile.NamedTemporaryFile(suffix=".tsq", delete=False) as fh:
        fh.write(query)
        question = fh.name
    try:
        result = subprocess.run(
            [binary, "ts", "-verify", "-in", reply, "-queryfile", question,
             "-CAfile", ca_file],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        token.note = f"could not run openssl to verify: {exc}"
        return
    finally:
        os.unlink(reply)
        os.unlink(question)

    output = (result.stdout + result.stderr).lower()
    token.verified = result.returncode == 0 and "verification: ok" in output
    token.verified_against = os.path.abspath(ca_file) if token.verified else ""
    if not token.verified:
        token.note = (f"the signature did not verify against {ca_file}: "
                      f"{(result.stderr or result.stdout).strip()[:200]}")
    else:
        token.note = ""


def verify_file(token_path: str, digest: bytes, ca_file: str) -> Token:
    """Check a token somebody hands you, years later, with no vault at all.

    This is the point of keeping the raw token: it stands on its own.
    """
    try:
        with open(token_path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise TimestampError(f"could not read that token: {exc}") from exc
    token = Token(digest=digest.hex(), authority=os.path.basename(token_path),
                  raw=raw)
    _read_reply(token)
    _verify(token, digest, ca_file)
    return token


# --------------------------------------------------------------------------
# what this vault has collected
# --------------------------------------------------------------------------

@dataclass
class StampReport:
    """What one round of stamping did."""

    token: Optional[Token] = None
    clock_corrected: float = 0.0
    written: str = ""
    problems: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.token is not None

    def summary(self) -> str:
        if self.token is None:
            return "; ".join(self.problems) or "No timestamp was obtained."
        parts = [f"Timestamped by {self.token.authority}."]
        if self.token.verified:
            parts.append("The signature verifies.")
        else:
            parts.append("The signature was not checked — no certificate "
                         "supplied, so this is a record, not proof.")
        if self.clock_corrected > 0:
            from . import expiry as expiry_mod
            parts.append(
                f"This machine's clock was {expiry_mod.format_duration(self.clock_corrected)} "
                f"behind; the vault has moved its watermark forward to match.")
        return " ".join(parts)


def stamp_anchor(vault, authority: str, ca_file: Optional[str] = None,
                 output_path: Optional[str] = None,
                 timeout: float = DEFAULT_TIMEOUT) -> StampReport:
    """Have an authority sign this vault's chain head.

    Signs the *fingerprint of the history*, not anything in the vault. The
    authority learns a 32-byte number and nothing else — not how many entries
    there are, not their names, not that this is a Quenchkey vault at all.
    """
    report = StampReport()
    head = vault.chain_head
    digest = anchor_digest(head)

    try:
        token = fetch(digest, authority, timeout=timeout, ca_file=ca_file,
                      covers=f"chain head {head[:16]}")
    except TimestampError as exc:
        report.problems.append(str(exc))
        return report

    report.token = token

    # The authority's opinion of the time is better than this machine's, so
    # the watermark takes it. Only ever forwards: a token with an earlier time
    # than the vault has already seen is either a replay or a broken
    # authority, and in both cases the ratchet is what protects the vault.
    if token.stamped:
        corrected = vault.observe_time(token.stamped,
                                       source=token.authority,
                                       verified=token.verified)
        report.clock_corrected = corrected

    if output_path:
        try:
            with open(output_path, "wb") as fh:
                fh.write(token.raw)
            report.written = os.path.abspath(output_path)
        except OSError as exc:
            report.problems.append(f"could not write the token: {exc}")

    collected = list(vault.note(NOTE_KEY) or [])
    collected.append({**token.to_dict(),
                      "chain_head": head,
                      "written": report.written})
    vault.set_note(NOTE_KEY, collected[-50:])
    vault.log_event("anchor_timestamped",
                    authority=token.authority,
                    stamped=token.stamped,
                    verified=token.verified,
                    chain_head=head)
    vault.save()
    return report


def collected(vault) -> list:
    """Every token this vault has obtained, newest last."""
    return [Token.from_dict(raw) for raw in (vault.note(NOTE_KEY) or [])]


def anchor_digest(chain_head: str) -> bytes:
    """What gets signed for a given chain head.

    A hash of the head under its own domain separator, so the authority is
    never handed anything that means something on its own, and so a token for
    an anchor can never be mistaken for a token for anything else.
    """
    return hashlib.sha256(b"quenchkey/anchor/v1" + chain_head.encode()).digest()


def verify_collected(vault, ca_file: str) -> list:
    """Re-check every token this vault has kept, against a certificate.

    Note which chain head each token covers. Stamping is itself an event, so
    a token signs the history as it stood *before* it was taken — which is
    exactly right, since nothing can sign a hash that includes its own
    signature, but it does mean the head to verify against is the one
    recorded beside the token rather than whatever the vault is on now.
    """
    results = []
    for raw in (vault.note(NOTE_KEY) or []):
        token = Token.from_dict(raw)
        written = raw.get("written") or ""
        head = raw.get("chain_head") or ""
        if not written or not os.path.exists(written) or not head:
            token.verified = False
            token.note = ("the token itself was not kept, so there is nothing "
                          "to re-check — only this vault's word for it")
            results.append(token)
            continue
        try:
            results.append(verify_file(written, anchor_digest(head), ca_file))
        except TimestampError as exc:
            token.verified = False
            token.note = str(exc)
            results.append(token)
    return results

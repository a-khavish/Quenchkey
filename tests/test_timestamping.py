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

"""Timestamps, against a real timestamp authority built for the occasion.

These tests stand up an actual RFC 3161 authority with openssl and talk to it
over HTTP, rather than mocking the protocol. A mocked timestamp proves that
the mock was called; what wants proving here is that a token this tool
requests is one openssl will verify years later against a certificate, and
that a token for the wrong thing is refused.

The whole file skips when openssl is missing, because then the feature itself
is honestly unavailable rather than broken.
"""

from __future__ import annotations

import hashlib
import http.server
import os
import shutil
import subprocess
import tempfile
import threading
import time

import pytest

from quenchkey import timestamping

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None,
                                reason="openssl is what verifies these tokens")

CONFIG = """\
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = .
serial = ./serial
database = ./index.txt
new_certs_dir = ./certs
certificate = ./cacert.pem
private_key = ./cakey.pem
default_days = 365
default_md = sha256
policy = policy_any
email_in_dn = no
unique_subject = no
[ policy_any ]
countryName = optional
stateOrProvinceName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
[ req ]
default_bits = 2048
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no
[ req_dn ]
CN = Quenchkey Test TSA Root
[ v3_ca ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
[ tsa_cert ]
basicConstraints = critical,CA:false
keyUsage = critical,nonRepudiation
extendedKeyUsage = critical,timeStamping
[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
dir = .
serial = ./tsaserial
crypto_device = builtin
signer_cert = ./tsacert.pem
certs = ./cacert.pem
signer_key = ./tsakey.pem
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_alg = sha256
"""


class Authority:
    """A real RFC 3161 authority, on a loopback port, for the test session."""

    def __init__(self, root: str):
        self.root = root
        self.ca_file = os.path.join(root, "cacert.pem")
        self.refuse = False
        self._build()
        self._serve()

    def _run(self, *args, **kwargs):
        return subprocess.run(args, cwd=self.root, capture_output=True,
                              timeout=120, **kwargs)

    def _build(self) -> None:
        os.makedirs(os.path.join(self.root, "certs"), exist_ok=True)
        with open(os.path.join(self.root, "openssl.cnf"), "w") as fh:
            fh.write(CONFIG)
        open(os.path.join(self.root, "index.txt"), "w").close()
        for name in ("serial", "tsaserial"):
            with open(os.path.join(self.root, name), "w") as fh:
                fh.write("01\n")
        self._run("openssl", "req", "-x509", "-newkey", "rsa:2048",
                  "-keyout", "cakey.pem", "-out", "cacert.pem", "-nodes",
                  "-days", "3650", "-config", "openssl.cnf")
        self._run("openssl", "req", "-new", "-newkey", "rsa:2048",
                  "-keyout", "tsakey.pem", "-out", "tsa.csr", "-nodes",
                  "-subj", "/CN=Quenchkey Test TSA")
        self._run("openssl", "ca", "-batch", "-config", "openssl.cnf",
                  "-extensions", "tsa_cert", "-in", "tsa.csr",
                  "-out", "tsacert.pem")
        assert os.path.exists(os.path.join(self.root, "tsacert.pem"))

    def _serve(self) -> None:
        authority = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server naming
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                if authority.refuse:
                    self.send_error(503, "the authority is having a day off")
                    return
                reply = authority.sign(body)
                if reply is None:
                    self.send_error(500, "could not sign")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/tsa"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def sign(self, request: bytes):
        with tempfile.NamedTemporaryFile(suffix=".tsq", delete=False) as fh:
            fh.write(request)
            question = fh.name
        answer = question + ".tsr"
        try:
            result = self._run("openssl", "ts", "-reply", "-config",
                               "openssl.cnf", "-queryfile", question,
                               "-out", answer)
            if result.returncode != 0 or not os.path.exists(answer):
                return None
            with open(answer, "rb") as fh:
                return fh.read()
        finally:
            for path in (question, answer):
                if os.path.exists(path):
                    os.unlink(path)

    def stop(self) -> None:
        self.server.shutdown()


@pytest.fixture(scope="module")
def authority():
    root = tempfile.mkdtemp(prefix="quenchkey-tsa-")
    made = Authority(root)
    yield made
    made.stop()
    shutil.rmtree(root, ignore_errors=True)


# --------------------------------------------------------------------------
# the request, which is built here rather than by a library
# --------------------------------------------------------------------------

def test_the_request_is_a_well_formed_timestamp_query(tmp_path):
    """Proved by openssl reading it back, not by reading the bytes."""
    digest = hashlib.sha256(b"whatever").digest()
    path = tmp_path / "request.tsq"
    path.write_bytes(timestamping.build_request(digest, nonce=0x1234))

    result = subprocess.run(["openssl", "ts", "-query", "-in", str(path), "-text"],
                            capture_output=True, text=True, timeout=60)

    assert result.returncode == 0
    assert "sha256" in result.stdout.lower()
    assert digest.hex()[:8] in result.stdout.replace(" ", "").lower() or \
        "Message data" in result.stdout


def test_only_the_digest_leaves_the_machine():
    """The authority is handed 32 bytes and learns nothing else."""
    digest = hashlib.sha256(b"the actual secret document").digest()

    request = timestamping.build_request(digest)

    assert digest in request
    assert b"the actual secret document" not in request
    assert len(request) < 128


def test_a_digest_of_the_wrong_length_is_refused():
    with pytest.raises(timestamping.TimestampError):
        timestamping.build_request(b"too short")


# --------------------------------------------------------------------------
# fetching, verifying, and refusing
# --------------------------------------------------------------------------

def test_a_token_comes_back_and_verifies(authority):
    digest = hashlib.sha256(b"anchor state").digest()

    token = timestamping.fetch(digest, authority.url, ca_file=authority.ca_file)

    assert token.verified
    assert abs(token.stamped - time.time()) < 300
    assert token.note == ""


def test_a_token_verifies_again_years_later_with_no_vault(authority, tmp_path):
    """The point of keeping the raw bytes: the token stands on its own."""
    digest = hashlib.sha256(b"anchor state").digest()
    token = timestamping.fetch(digest, authority.url, ca_file=authority.ca_file)
    path = tmp_path / "anchor.tsr"
    path.write_bytes(token.raw)

    again = timestamping.verify_file(str(path), digest, authority.ca_file)

    assert again.verified
    assert abs(again.stamped - token.stamped) < 2


def test_a_token_for_something_else_does_not_verify(authority, tmp_path):
    token = timestamping.fetch(hashlib.sha256(b"one thing").digest(),
                               authority.url, ca_file=authority.ca_file)
    path = tmp_path / "anchor.tsr"
    path.write_bytes(token.raw)

    other = timestamping.verify_file(
        str(path), hashlib.sha256(b"a different thing").digest(),
        authority.ca_file)

    assert not other.verified


def test_a_token_does_not_verify_against_the_wrong_certificate(
        authority, tmp_path):
    digest = hashlib.sha256(b"anchor state").digest()
    token = timestamping.fetch(digest, authority.url, ca_file=authority.ca_file)
    path = tmp_path / "anchor.tsr"
    path.write_bytes(token.raw)
    stranger = tmp_path / "stranger.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", str(tmp_path / "k.pem"), "-out", str(stranger),
                    "-nodes", "-days", "30", "-subj", "/CN=Somebody Else"],
                   capture_output=True, timeout=120)

    checked = timestamping.verify_file(str(path), digest, str(stranger))

    assert not checked.verified
    assert "did not verify" in checked.note


def test_without_a_certificate_it_says_so_rather_than_claiming_proof(authority):
    """A green tick it has not earned would be worse than no tick."""
    digest = hashlib.sha256(b"anchor state").digest()

    token = timestamping.fetch(digest, authority.url)

    assert token.stamped > 0
    assert not token.verified
    assert "not been checked" in token.note
    assert "not verified" in token.describe()


def test_an_authority_that_cannot_be_reached_is_not_a_vault_failure():
    with pytest.raises(timestamping.Offline) as raised:
        timestamping.fetch(hashlib.sha256(b"x").digest(),
                           "http://127.0.0.1:9/nothing-here", timeout=2)

    assert "still enforced" in str(raised.value)


def test_an_authority_that_refuses_says_why(authority):
    authority.refuse = True
    try:
        with pytest.raises(timestamping.TimestampError):
            timestamping.fetch(hashlib.sha256(b"x").digest(), authority.url,
                               timeout=10)
    finally:
        authority.refuse = False


# --------------------------------------------------------------------------
# what it does for the vault
# --------------------------------------------------------------------------

def test_stamping_the_anchor_records_it_in_the_chain(vault, authority, tmp_path):
    report = timestamping.stamp_anchor(
        vault, authority.url, ca_file=authority.ca_file,
        output_path=str(tmp_path / "anchor.tsr"))

    assert report.ok and report.token.verified
    assert any(e.get("kind") == "anchor_timestamped" for e in vault.events)
    assert vault.chain_report().ok
    assert os.path.exists(report.written)


def test_the_token_covers_the_head_it_was_taken_at(vault, authority, tmp_path):
    """Stamping is itself an event, so nothing can sign its own signature."""
    timestamping.stamp_anchor(vault, authority.url, ca_file=authority.ca_file,
                              output_path=str(tmp_path / "anchor.tsr"))

    rechecked = timestamping.verify_collected(vault, authority.ca_file)

    assert len(rechecked) == 1
    assert rechecked[0].verified


def test_a_clock_set_back_is_put_right_by_the_authority(vault, authority,
                                                        tmp_path):
    """The whole point of asking somebody else what time it is."""
    behind = time.time() - 30 * 86400
    vault._last_seen = behind

    report = timestamping.stamp_anchor(vault, authority.url,
                                       ca_file=authority.ca_file,
                                       output_path=str(tmp_path / "a.tsr"))

    assert report.clock_corrected > 29 * 86400
    assert vault.effective_now() >= report.token.stamped
    assert "behind" in report.summary()


def test_the_watermark_only_ever_moves_forward(vault):
    """A reading from the past is a replay or a broken source. Ignored."""
    ahead = time.time() + 86400
    vault.observe_time(ahead, source="test")

    moved = vault.observe_time(time.time() - 86400, source="a liar")

    assert moved == 0.0
    assert vault.effective_now() >= ahead


def test_an_observed_time_is_written_into_the_chain(vault):
    vault.observe_time(time.time() + 3600, source="somewhere", verified=True)

    observed = [e for e in vault.events if e.get("kind") == "clock_observed"]
    assert len(observed) == 1
    assert observed[0]["source"] == "somewhere"
    assert observed[0]["verified"] is True
    assert vault.chain_report().ok


def test_a_token_that_was_not_kept_is_honest_about_it(vault, authority):
    """No file means nothing to re-check, and it says that rather than 'ok'."""
    timestamping.stamp_anchor(vault, authority.url, ca_file=authority.ca_file)

    rechecked = timestamping.verify_collected(vault, authority.ca_file)

    assert not rechecked[0].verified
    assert "only this vault's word" in rechecked[0].note


def test_the_authority_never_sees_what_is_in_the_vault(vault, authority,
                                                       workspace, tmp_path):
    """It is handed a hash of a hash, under its own domain separator."""
    from quenchkey import locker

    source = workspace / "documents" / "secret-merger.txt"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"project codename is falconry " * 50)
    locker.lock_files(vault, [str(source)], time.time() + 7200,
                      output_dir=str(workspace / "locked"))

    seen: list = []
    original = timestamping.build_request

    def watched(digest, **kwargs):
        seen.append(digest)
        return original(digest, **kwargs)

    timestamping.build_request = watched
    try:
        timestamping.stamp_anchor(vault, authority.url,
                                  ca_file=authority.ca_file,
                                  output_path=str(tmp_path / "a.tsr"))
    finally:
        timestamping.build_request = original

    assert seen
    for digest in seen:
        assert len(digest) == 32
        assert b"falconry" not in digest
        assert b"secret-merger" not in digest

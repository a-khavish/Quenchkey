"""The primitives, and the properties everything else relies on."""

from __future__ import annotations

import os

import pytest

from quenchkey import crypto
from quenchkey.crypto import AuthenticationError, SecretBytes, UnsupportedFormat


def test_round_trip_both_ciphers():
    key = SecretBytes.random()
    for cipher_id in (crypto.CIPHER_CHACHA20_POLY1305, crypto.CIPHER_AES_256_GCM):
        nonce, sealed = crypto.encrypt(key, b"the payload", b"header", cipher_id)
        assert crypto.decrypt(key, nonce, sealed, b"header", cipher_id) == b"the payload"


def test_wrong_key_fails():
    nonce, sealed = crypto.encrypt(SecretBytes.random(), b"x", b"")
    with pytest.raises(AuthenticationError):
        crypto.decrypt(SecretBytes.random(), nonce, sealed, b"")


def test_modified_associated_data_fails():
    key = SecretBytes.random()
    nonce, sealed = crypto.encrypt(key, b"payload", b"v1")
    with pytest.raises(AuthenticationError):
        crypto.decrypt(key, nonce, sealed, b"v2")


@pytest.mark.parametrize("position", [0, 5, -1])
def test_flipping_any_ciphertext_bit_fails(position):
    key = SecretBytes.random()
    nonce, sealed = crypto.encrypt(key, b"a longer payload to flip bits in", b"aad")
    damaged = bytearray(sealed)
    damaged[position] ^= 0x01
    with pytest.raises(AuthenticationError):
        crypto.decrypt(key, nonce, bytes(damaged), b"aad")


def test_unknown_cipher_id_is_rejected():
    with pytest.raises(UnsupportedFormat):
        crypto.encrypt(SecretBytes.random(), b"x", b"", cipher_id=99)


def test_secret_bytes_wipe_and_never_leaks_in_repr():
    secret = SecretBytes(b"\x01" * 32)
    assert "01" not in repr(secret) and "\x01" not in str(secret)
    assert not secret.is_zero()
    secret.wipe()
    assert secret.is_zero() and secret.wiped
    with pytest.raises(crypto.CryptoError):
        secret.bytes()


def test_secret_bytes_compares_in_constant_time_api():
    assert SecretBytes(b"a" * 32) == SecretBytes(b"a" * 32)
    assert SecretBytes(b"a" * 32) != SecretBytes(b"b" * 32)


def test_key_derivation_is_deterministic_and_salt_dependent():
    params = crypto.KdfParams.create(1, 8192, 1)
    other = crypto.KdfParams(os.urandom(16), 1, 8192, 1)
    first = crypto.derive_master_key(crypto.build_kdf_input("passphrase"), params)
    again = crypto.derive_master_key(crypto.build_kdf_input("passphrase"), params)
    different_salt = crypto.derive_master_key(crypto.build_kdf_input("passphrase"), other)
    assert first == again
    assert first != different_salt


def test_keyfile_changes_the_derived_key(tmp_path):
    from quenchkey import keyfile

    path = str(tmp_path / "k.keyfile")
    keyfile.generate(path)
    params = crypto.KdfParams.create(1, 8192, 1)
    without = crypto.derive_master_key(crypto.build_kdf_input("pass"), params)
    with_file = crypto.derive_master_key(crypto.build_kdf_input("pass", path), params)
    assert without != with_file


def test_kdf_params_reject_absurd_values():
    for bad in (crypto.KdfParams(b"\x00" * 16, 0, 8192, 1),
                crypto.KdfParams(b"\x00" * 16, 1, 1, 1),
                crypto.KdfParams(b"\x00" * 16, 1, 8192, 0),
                crypto.KdfParams(b"\x00" * 4, 1, 8192, 1)):
        with pytest.raises(UnsupportedFormat):
            bad.validate()


def test_chunk_nonces_never_repeat_within_a_file():
    prefix = os.urandom(4)
    seen = {crypto.chunk_nonce(prefix, i) for i in range(5000)}
    assert len(seen) == 5000


def test_chunk_aad_binds_index_and_end_flag():
    header = b"header"
    assert crypto.chunk_aad(header, 1, False) != crypto.chunk_aad(header, 2, False)
    assert crypto.chunk_aad(header, 1, False) != crypto.chunk_aad(header, 1, True)


def test_calibration_lands_near_its_target():
    params = crypto.calibrate_kdf(target_seconds=0.2, memory_kib=16384, parallelism=1)
    params.validate()
    assert params.time_cost >= 1
    assert params.memory_kib >= 8

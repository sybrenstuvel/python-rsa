#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Tests integer operations."""

from typing import Tuple
import pytest
import rsa
import rsa.core


@pytest.fixture(scope="module")
def rsa_keys() -> Tuple[rsa.PublicKey, rsa.PrivateKey]:
    return rsa.new_keys(64)


def encrypt_decrypt_test_case(message: int, public: rsa.PublicKey, private: rsa.PrivateKey) -> int:
    encrypted = rsa.core.encrypt_int(message, public.e, public.n)
    decrypted = rsa.core.decrypt_int(encrypted, private.d, public.n)
    return decrypted


def test_encrypt_decrypt(rsa_keys: Tuple[rsa.PublicKey, rsa.PrivateKey]) -> None:
    public, private = rsa_keys
    message = 42

    decrypted_message = encrypt_decrypt_test_case(message, public, private)
    assert message == decrypted_message


def sign_verify_test_case(message: int, public_key: rsa.PublicKey, private_key: rsa.PrivateKey) -> int:
    signed = rsa.core.encrypt_int(message, private_key.d, public_key.n)
    verified = rsa.core.decrypt_int(signed, public_key.e, public_key.n)
    return verified


def test_sign_verify(rsa_keys: Tuple[rsa.PublicKey, rsa.PrivateKey]) -> None:
    public, private = rsa_keys
    message = 42

    verified_message = sign_verify_test_case(message, public, private)
    assert message == verified_message


@pytest.mark.parametrize("message", [-1, 0, 1])
def test_extreme_values(rsa_keys: Tuple[rsa.PublicKey, rsa.PrivateKey], message: int) -> None:
    public_key, private_key = rsa_keys

    if message < 0:
        with pytest.raises(ValueError):
            rsa.core.encrypt_int(message, public_key.e, public_key.n)
    elif message == 0:
        decrypted_message = encrypt_decrypt_test_case(message, public_key, private_key)
        assert message == decrypted_message
    else:
        with pytest.raises(OverflowError):
            rsa.core.encrypt_int(public_key.n, public_key.e, public_key.n)

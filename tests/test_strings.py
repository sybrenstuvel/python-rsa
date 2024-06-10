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

"""Tests string operations."""

import pytest

import rsa

unicode_string = "Euro=\u20ac ABCDEFGHIJKLMNOPQRSTUVWXYZ"


@pytest.fixture
def rsa_keys():
    public, private = rsa.new_keys(384)
    return public, private


def test_enc_dec(rsa_keys):
    public, private = rsa_keys
    message = unicode_string.encode("utf-8")
    print("\n\tMessage:   %r" % message)

    encrypted = rsa.encrypt(message, public)
    print("\tEncrypted: %r" % encrypted)

    decrypted = rsa.decrypt(encrypted, private)
    print("\tDecrypted: %r" % decrypted)

    assert message == decrypted

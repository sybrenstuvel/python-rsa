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

import unittest

import rsa
import rsa.core


class IntegerTest(unittest.TestCase):
    def setUp(self):
        (self.pub, self.priv) = rsa.newkeys(64)

    def test_enc_dec(self):
        message = 42
        print("\n\tMessage:   %d" % message)

        encrypted = rsa.core.encrypt_int(message, self.pub.e, self.pub.n)
        print("\tEncrypted: %d" % encrypted)

        decrypted = rsa.core.decrypt_int(encrypted, self.priv.d, self.pub.n)
        print("\tDecrypted: %d" % decrypted)

        self.assertEqual(message, decrypted)

    def test_sign_verify(self):
        message = 42

        signed = rsa.core.encrypt_int(message, self.priv.d, self.pub.n)
        print("\n\tSigned:    %d" % signed)

        verified = rsa.core.decrypt_int(signed, self.pub.e, self.pub.n)
        print("\tVerified:  %d" % verified)

        self.assertEqual(message, verified)

    def test_extreme_values(self):
        # message < 0
        message = -1
        print("\n\tMessage:   %d" % message)

        with self.assertRaises(ValueError):
            rsa.core.encrypt_int(message, self.pub.e, self.pub.n)

        # message == 0
        message = 0
        print("\n\tMessage:   %d" % message)

        encrypted = rsa.core.encrypt_int(message, self.pub.e, self.pub.n)
        print("\tEncrypted: %d" % encrypted)

        decrypted = rsa.core.decrypt_int(encrypted, self.priv.d, self.pub.n)
        print("\tDecrypted: %d" % decrypted)

        self.assertEqual(message, decrypted)

        # message >= n
        message = self.pub.n
        print("\n\tMessage:   %d" % message)

        with self.assertRaises(OverflowError):
            rsa.core.encrypt_int(message, self.pub.e, self.pub.n)


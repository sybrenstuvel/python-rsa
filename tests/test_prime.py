# -*- coding: utf-8 -*-
#
#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Tests prime functions."""

import unittest

import rsa.prime
import rsa.randnum


class PrimeTest(unittest.TestCase):
    def test_is_prime(self):
        """Test some common primes."""

        # Test some trivial numbers
        self.assertFalse(rsa.prime.is_prime(-1))
        self.assertFalse(rsa.prime.is_prime(0))
        self.assertFalse(rsa.prime.is_prime(1))
        self.assertTrue(rsa.prime.is_prime(2))
        self.assertFalse(rsa.prime.is_prime(42))
        self.assertTrue(rsa.prime.is_prime(41))

        # Test some slightly larger numbers
        self.assertEqual(
            [907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997],
            [x for x in range(901, 1000) if rsa.prime.is_prime(x)]
        )

        # Test around the 50th millionth known prime.
        self.assertTrue(rsa.prime.is_prime(982451653))
        self.assertFalse(rsa.prime.is_prime(982451653 * 961748941))

    def test_miller_rabin_primality_testing(self):
        """Uses monkeypatching to ensure certain random numbers.

        This allows us to predict/control the code path.
        """

        randints = []

        def fake_randint(maxvalue):
            return randints.pop(0)

        orig_randint = rsa.randnum.randint
        rsa.randnum.randint = fake_randint
        try:
            # 'n is composite'
            randints.append(2630484831)  # causes the 'n is composite' case with n=3784949785
            self.assertEqual(False, rsa.prime.miller_rabin_primality_testing(2787998641, 7))
            self.assertEqual([], randints)

            # 'Exit inner loop and continue with next witness'
            randints.extend([
                2119139097,  # causes 'Exit inner loop and continue with next witness'
                # the next witnesses for the above case:
                3051067715, 3603501762, 3230895846, 3687808132, 3760099986, 4026931494, 3022471881,
            ])
            self.assertEqual(True, rsa.prime.miller_rabin_primality_testing(2211417913,
                                                                            len(randints)))
            self.assertEqual([], randints)
        finally:
            rsa.randnum.randint = orig_randint

    def test_get_primality_testing_rounds(self):
        """Test round calculation for primality testing."""

        self.assertEquals(rsa.prime.get_primality_testing_rounds(1 << 63),  10)
        self.assertEquals(rsa.prime.get_primality_testing_rounds(1 << 127), 10)
        self.assertEquals(rsa.prime.get_primality_testing_rounds(1 << 255), 10)
        self.assertEquals(rsa.prime.get_primality_testing_rounds(1 << 511),  7)
        self.assertEquals(rsa.prime.get_primality_testing_rounds(1 << 767),  7)
        self.assertEquals(rsa.prime.get_primality_testing_rounds(1 << 1023), 4)
        self.assertEquals(rsa.prime.get_primality_testing_rounds(1 << 1279), 4)
        self.assertEquals(rsa.prime.get_primality_testing_rounds(1 << 1535), 3)
        self.assertEquals(rsa.prime.get_primality_testing_rounds(1 << 2047), 3)
        self.assertEquals(rsa.prime.get_primality_testing_rounds(1 << 4095), 3)

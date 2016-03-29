"""
Some tests for the rsa/key.py file.
"""

import unittest

import rsa.key
import rsa.core


class BlindingTest(unittest.TestCase):
    def test_blinding(self):
        """Test blinding and unblinding.

        This is basically the doctest of the PrivateKey.blind method, but then
        implemented as unittest to allow running on different Python versions.
        """

        pk = rsa.key.PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)

        message = 12345
        encrypted = rsa.core.encrypt_int(message, pk.e, pk.n)

        blinded = pk.blind(encrypted, 4134431)  # blind before decrypting
        decrypted = rsa.core.decrypt_int(blinded, pk.d, pk.n)
        unblinded = pk.unblind(decrypted, 4134431)

        self.assertEqual(unblinded, message)


class KeyGenTest(unittest.TestCase):
    def test_custom_exponent(self):
        priv, pub = rsa.key.newkeys(16, exponent=3)

        self.assertEqual(3, priv.e)
        self.assertEqual(3, pub.e)

    def test_default_exponent(self):
        priv, pub = rsa.key.newkeys(16)

        self.assertEqual(0x10001, priv.e)
        self.assertEqual(0x10001, pub.e)

    def test_custom_getprime_func(self):
        # List of primes to test with, in order [p, q, p, q, ....]
        primes = [64123, 50957, 39317, 33107]

        def getprime(_):
            return primes.pop(0)

        # This exponent will cause two other primes to be generated.
        exponent = 136407

        (p, q, e, d) = rsa.key.gen_keys(64,
                                        accurate=False,
                                        getprime_func=getprime,
                                        exponent=exponent)
        self.assertEqual(39317, p)
        self.assertEqual(33107, q)

"""
Some tests for the rsa/key.py file.
"""

import unittest

import rsa.key
import rsa.logic


class BlindingTest(unittest.TestCase):
    def test_blinding(self):
        """Test blinding and unblinding.

        This is basically the doctest of the PrivateKey.blind method, but then
        implemented as unittest to allow running on different Python versions.
        """

        pk = rsa.key.PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)

        message = 12345
        encrypted = rsa.logic.encrypt_int(message, pk.e, pk.n)

        blinded_1, unblind_1 = pk.blind(encrypted)  # blind before decrypting
        decrypted = rsa.logic.decrypt_int(blinded_1, pk.d, pk.n)
        unblinded_1 = pk.unblind(decrypted, unblind_1)

        self.assertEqual(unblinded_1, message)

        # Re-blinding should use a different blinding factor.
        blinded_2, unblind_2 = pk.blind(encrypted)  # blind before decrypting
        self.assertNotEqual(blinded_1, blinded_2)

        # The unblinding should still work, though.
        decrypted = rsa.logic.decrypt_int(blinded_2, pk.d, pk.n)
        unblinded_2 = pk.unblind(decrypted, unblind_2)
        self.assertEqual(unblinded_2, message)


class KeyGenTest(unittest.TestCase):
    def test_custom_exponent(self):
        public, private = rsa.key.new_keys(16, exponent=3)

        self.assertEqual(3, private.e)
        self.assertEqual(3, public.e)

    def test_default_exponent(self):
        public, private = rsa.key.new_keys(16)

        self.assertEqual(0x10001, private.e)
        self.assertEqual(0x10001, public.e)

    def test_exponents_coefficient_calculation(self):
        pk = rsa.key.PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)

        self.assertEqual(pk.exp1, 55063)
        self.assertEqual(pk.exp2, 10095)
        self.assertEqual(pk.coef, 50797)

    def test_custom_get_prime_func(self):
        # List of primes to test with, in order [p, q, p, q, ....]
        # By starting with two of the same primes, we test that this is
        # properly rejected.
        primes = [64123, 64123, 64123, 50957, 39317, 33107]

        def get_prime(_):
            return primes.pop(0)

        # This exponent will cause two other primes to be generated.
        exponent = 136407

        (p, q, e, d) = rsa.key.gen_keys(
            64, accurate=False, get_prime_func=get_prime, exponent=exponent
        )
        self.assertEqual(39317, p)
        self.assertEqual(33107, q)

    def test_multiprime(self):
        primes = [64123, 50957, 39317, 33107]
        exponent = 2**2**4 + 1

        def getprime(_):
            return primes.pop(0)
        (p, q, e, d, rs) = rsa.key.gen_keys(
            128,
            accurate=False,
            get_prime_func=getprime,
            exponent=exponent,
            n_primes=4
        )
        self.assertEqual(64123, p)
        self.assertEqual(50957, q)
        self.assertEqual(rs, [39317, 33107])


class HashTest(unittest.TestCase):
    """Test hashing of keys"""

    def test_hash_possible(self):
        pub, priv = rsa.key.new_keys(16)

        # This raises a TypeError when hashing isn't possible.
        hash(priv)
        hash(pub)

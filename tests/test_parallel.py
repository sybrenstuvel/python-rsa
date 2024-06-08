"""Test for multiprocess prime generation."""

import unittest

import rsa.prime
import rsa.parallel
import rsa.helpers as helpers_namespace


class ParallelTest(unittest.TestCase):
    """Tests for multiprocess prime generation."""

    def test_parallel_primegen(self):
        p = rsa.parallel.get_prime(1024, 3)

        self.assertFalse(rsa.prime.is_prime(p - 1))
        self.assertTrue(rsa.prime.is_prime(p))
        self.assertFalse(rsa.prime.is_prime(p + 1))

        self.assertEqual(1024, helpers_namespace.bit_size(p))

"""Test for multiprocess prime generation."""

import rsa.helpers as helpers_namespace
import rsa.parallel
import rsa.prime


def test_parallel_primegen():
    p = rsa.parallel.get_prime(1024, 3)
    assert helpers_namespace.bit_size(p) == 1024

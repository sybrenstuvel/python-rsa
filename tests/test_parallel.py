"""Test for multiprocess prime generation."""

import rsa.helpers as helpers_namespace
import rsa.utils as utils_namespace


def test_parallel_primegen():
    p = utils_namespace.get_prime(1024, 3)
    assert helpers_namespace.bit_size(p) == 1024

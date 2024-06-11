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

"""Functions for parallel computation on multiple cores.

Introduced in Python-RSA 3.1.

.. note::

    Requires Python 2.6 or newer.

"""

import multiprocessing as mp
from multiprocessing.connection import Connection

import sympy
import math
import rsa.utils.randnum

__all__ = ["get_prime", "are_relatively_prime"]


def are_relatively_prime(a: int, b: int) -> bool:
    """Returns True if a and b are relatively prime, and False if they
    are not.

    >>> are_relatively_prime(2, 3)
    True
    >>> are_relatively_prime(2, 4)
    False
    """

    return math.gcd(a, b) == 1


def get_prime(nbits: int, pool_size: int = 1) -> int:
    """
    interface between multiprocessing and single.
    """
    if pool_size == 1:
        return _get_prime_single_thread(n_bits=nbits)
    return _get_prime_multi_thread(nbits=nbits, pool_size=pool_size)


def _find_prime(nbits: int, pipe: Connection) -> None:
    """Finds a prime number and sends it through the pipe."""
    while True:
        integer = rsa.utils.randnum.read_random_odd_int(nbits)

        if sympy.isprime(integer):
            pipe.send(integer)
            return


def _get_prime_multi_thread(nbits: int, pool_size: int) -> int:
    """Returns a prime number that can be stored in 'nbits' bits.

        Works in multiple threads at the same time.

        >>> import sympy
        >>> p = get_prime(128, 3)
        >>> sympy.isprime(p-1)
        False
        >>> sympy.isprime(p)
        True
        >>> sympy.isprime(p+1)
        False

        >>> from rsa.helpers import common
        >>> common.bit_size(p) == 128
        True
        """
    pipe_recv, pipe_send = mp.Pipe(duplex=False)
    procs = [mp.Process(target=_find_prime, args=(nbits, pipe_send)) for _ in range(pool_size)]

    try:
        for p in procs:
            p.start()

        result = pipe_recv.recv()
    finally:
        pipe_recv.close()
        pipe_send.close()

        for p in procs:
            p.terminate()
            p.join()

    return result


def _get_prime_single_thread(n_bits: int) -> int:
    """Returns a prime number that can be stored in 'nbits' bits.

    >>> from sympy import isprime
    >>> p = get_prime(128)
    >>> isprime(p-1)
    False
    >>> isprime(p)
    True
    >>> isprime(p+1)
    False

    >>> from rsa.helpers import common
    >>> common.bit_size(p) == 128
    True
    """

    assert n_bits > 3  # the loop will hang on too small numbers

    while True:
        integer = rsa.utils.randnum.read_random_odd_int(n_bits)

        # Test for primeness
        if sympy.isprime(integer):
            return integer


if __name__ == "__main__":
    print("Running doctests 100x or until failure")
    import doctest

    for count in range(100):
        failures, tests = doctest.testmod()
        if failures:
            break

        if count % 10 == 0 and count:
            print(f"{count} times")

    print("Doctests done")

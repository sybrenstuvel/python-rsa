# -*- coding: utf-8 -*-
#
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

"""Numerical functions related to primes.

Implementation based on the book Algorithm Design by Michael T. Goodrich and
Roberto Tamassia, 2002.
"""

from rsa._compat import range
import rsa.common
import rsa.randnum

__all__ = ['getprime', 'are_relatively_prime']


def gcd(p, q):
    """Returns the greatest common divisor of p and q

    >>> gcd(48, 180)
    12
    """

    while q != 0:
        (p, q) = (q, p % q)
    return p


def get_primality_testing_rounds(number):
    """Returns minimum number of rounds for Miller-Rabing primality testing,
    based on number bitsize.

    According to NIST FIPS 186-4, Appendix C, Table C.3, minimum number of
    rounds of M-R testing, using an error probability of 2 ** (-100), for
    different p, q bitsizes are:
      * p, q bitsize: 512; rounds: 7
      * p, q bitsize: 1024; rounds: 4
      * p, q bitsize: 1536; rounds: 3
    See: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    # Calculate number bitsize.
    bitsize = rsa.common.bit_size(number)
    # Set number of rounds.
    if bitsize >= 1536:
        return 3
    if bitsize >= 1024:
        return 4
    if bitsize >= 512:
        return 7
    # For smaller bitsizes, set arbitrary number of rounds.
    return 10


def miller_rabin_primality_testing(n, k):
    """Calculates whether n is composite (which is always correct) or prime
    (which theoretically is incorrect with error probability 4**-k), by
    applying Miller-Rabin primality testing.

    For reference and implementation example, see:
    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

    :param n: Integer to be tested for primality.
    :type n: int
    :param k: Number of rounds (witnesses) of Miller-Rabin testing.
    :type k: int
    :return: False if the number is composite, True if it's probably prime.
    :rtype: bool
    """

    # prevent potential infinite loop when d = 0
    if n < 2:
        return False

    # Decompose (n - 1) to write it as (2 ** r) * d
    # While d is even, divide it by 2 and increase the exponent.
    d = n - 1
    r = 0

    while not (d & 1):
        r += 1
        d >>= 1

    # Test k witnesses.
    for _ in range(k):
        # Generate random integer a, where 2 <= a <= (n - 2)
        a = rsa.randnum.randint(n - 3) + 1

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == 1:
                # n is composite.
                return False
            if x == n - 1:
                # Exit inner loop and continue with next witness.
                break
        else:
            # If loop doesn't break, n is composite.
            return False

    return True


def is_prime(number):
    """Returns True if the number is prime, and False otherwise.

    >>> is_prime(2)
    True
    >>> is_prime(42)
    False
    >>> is_prime(41)
    True
    """

    # Check for small numbers.
    if number < 10:
        return number in {2, 3, 5, 7}

    # Check for even numbers.
    if not (number & 1):
        return False

    # Calculate minimum number of rounds.
    k = get_primality_testing_rounds(number)

    # Run primality testing with (minimum + 1) rounds.
    return miller_rabin_primality_testing(number, k + 1)


def getprime(nbits):
    """Returns a prime number that can be stored in 'nbits' bits.

    >>> p = getprime(128)
    >>> is_prime(p-1)
    False
    >>> is_prime(p)
    True
    >>> is_prime(p+1)
    False

    >>> from rsa import common
    >>> common.bit_size(p) == 128
    True
    """

    assert nbits > 3  # the loop wil hang on too small numbers

    while True:
        integer = rsa.randnum.read_random_odd_int(nbits)

        # Test for primeness
        if is_prime(integer):
            return integer

            # Retry if not prime

small_primes=(3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
              67, 71, 73, 79, 83, 89, 97)
def prime_sieve(start,end):
    """for numbers in range(start,end) sieves out composites using trial
    division returning potential primes

    >>> sieve=prime_sieve(100,120)
    >>> next(sieve)
    101
    >>> [x for x in sieve]
    [103, 107, 109, 113]
    """

    #handle small numbers
    if start<=small_primes[-1]:
        if start<=2:yield 2
        for p in small_primes:
            if p<=start:yield p
    start|=1#make start odd
    #We use an offset when doing the trial divisions. It is much smaller than
    #the full number. This makes the modulo operations fast. When yielding a
    #candidate we add the start and offset to get the candidate value.
    residues=tuple((-start%p,p) for p in small_primes)
    #start+offset=0 (mod p) <---condition to check for
    #offset=-start (mod p)
    #offset%p=(-start)%p <--that's the residue
    offset=0
    span=end-start
    while offset<span:
        for residue,p in residues:
            if (offset%p)==residue:break
        else:#all trial divisions were successful
            yield start+offset
        offset+=2

def getprimebyrange(start,end,initial=None):
    """Returns a prime number randomly chosen from range(start,end)

    randomly chooses an initial point within the range
    This can be overriden with the optional initial argument

    starts at the initial point scanning range(initial,end) then trying
    range(start,initial)

    >>> p = getprimebyrange(100,200)
    >>> 100<=p<200
    True
    >>> is_prime(p-1)
    False
    >>> is_prime(p)
    True
    >>> is_prime(p+1)
    False

    >>> getprimebyrange(10000,20000,initial=10000)
    10007
    >>> getprimebyrange(10000,20000,initial=10010)
    10037
    >>> #when no primes in range(initial,end), it tries range(start,initial)
    >>> getprimebyrange(10000,10020,initial=10010)
    10007
    """
    #randomly choose the initial point in the range (unless specified)
    if initial is None:
        initial=rsa.randnum.randrange(start, end)
    #check top part of range
    for candidate in prime_sieve(initial, end):
        # Test for primeness
        if is_prime(candidate):
            return candidate
    #nothing in the top part of the given range
    #check bottom part of range
    for candidate in prime_sieve(start, initial):
        #integer = rsa.randnum.read_random_odd_int(nbits)
        # Test for primeness
        if is_prime(candidate):
            return candidate
    #nothing the bottom half either
    raise ValueError("no primes in range")


def are_relatively_prime(a, b):
    """Returns True if a and b are relatively prime, and False if they
    are not.

    >>> are_relatively_prime(2, 3)
    True
    >>> are_relatively_prime(2, 4)
    False
    """

    d = gcd(a, b)
    return d == 1


if __name__ == '__main__':
    print('Running doctests 1000x or until failure')
    import doctest

    for count in range(1000):
        (failures, tests) = doctest.testmod()
        if failures:
            break

        if count and count % 100 == 0:
            print('%i times' % count)

    print('Doctests done')

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

"""Core mathematical operations.

This is the actual core RSA implementation, which is only defined
mathematically on integers.
"""
import itertools
import typing


def assert_int(var: int, name: str) -> None:
    if isinstance(var, int):
        return

    raise TypeError("{} should be an integer, not {}".format(name, var.__class__))


def encrypt_int(message: int, ekey: int, n: int) -> int:
    """Encrypts a message using encryption key 'ekey', working modulo n"""

    assert_int(message, "message")
    assert_int(ekey, "ekey")
    assert_int(n, "n")

    if message < 0:
        raise ValueError("Only non-negative numbers are supported")

    if message >= n:
        raise OverflowError("The message %i is too long for n=%i" % (message, n))

    return pow(message, ekey, n)


def decrypt_int(cyphertext: int, dkey: int, n: int) -> int:
    """Decrypts a cypher text using the decryption key 'dkey', working modulo n"""

    assert_int(cyphertext, "cyphertext")
    assert_int(dkey, "dkey")
    assert_int(n, "n")

    message = pow(cyphertext, dkey, n)
    return message


def decrypt_int_fast(
    cyphertext: int,
    rs: typing.List[int],
    ds: typing.List[int],
    ts: typing.List[int],
) -> int:
    """Decrypts a cypher text more quickly using the Chinese Remainder Theorem."""

    assert_int(cyphertext, "cyphertext")
    for r in rs:
        assert_int(r, "r")
    for d in ds:
        assert_int(d, "d")
    for t in ts:
        assert_int(t, "t")

    p, q, rs = rs[0], rs[1], rs[2:]
    exp1, exp2, ds = ds[0], ds[1], ds[2:]
    coef, ts = ts[0], ts[1:]

    M1 = pow(cyphertext, exp1, p)
    M2 = pow(cyphertext, exp2, q)
    h = ((M1 - M2) * coef) % p
    m = M2 + q * h

    Ms = [pow(cyphertext, d, r) for d, r in zip(ds, rs)]
    Rs = list(itertools.accumulate([p, q] + rs, lambda x, y: x*y))
    for R, r, M, t in zip(Rs[1:], rs, Ms, ts):
        h = ((M - m) * t) % r
        m += R * h

    return m
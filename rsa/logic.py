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
import logging
import typing
import rsa.core as core_namespace

logger = logging.getLogger(__name__)


def encrypt_int(message: int, encrypt_key: int, n: int) -> int:
    """Encrypts a message using encryption key 'encrypt_key', working modulo n"""

    core_namespace.assert_int(message, "message")
    core_namespace.assert_int(encrypt_key, "encrypt_key")
    core_namespace.assert_int(n, "n")

    if message < 0:
        raise ValueError("Only non-negative numbers are supported")

    if message >= n:
        raise OverflowError(f"The message {message} is too long for n={n}")

    result = pow(message, encrypt_key, n)

    logger.debug(f"encrypt_int({message=}, {encrypt_key=}, {n=}) => {result=}")

    return result


def decrypt_int(cypher_text: int, decryption_key: int, n: int) -> int:
    """Decrypts a cypher text using the decryption key 'dkey', working modulo n"""

    core_namespace.assert_int(cypher_text, "cypher_text")
    core_namespace.assert_int(decryption_key, "dkey")
    core_namespace.assert_int(n, "n")

    result = pow(cypher_text, decryption_key, n)

    logger.debug(f"decrypt_int({cypher_text}, {decryption_key}) => {result=}")

    return result


def decrypt_int_fast(
        cypher_text: int,
        rs: typing.List[int],
        ds: typing.List[int],
        ts: typing.List[int],
) -> int:
    """Decrypts a cypher text more quickly using the Chinese Remainder Theorem."""

    core_namespace.assert_int(cypher_text, "cypher_text")
    for r in rs:
        core_namespace.assert_int(r, "r")
    for d in ds:
        core_namespace.assert_int(d, "d")
    for t in ts:
        core_namespace.assert_int(t, "t")

    p, q, rs = rs[0], rs[1], rs[2:]
    exp1, exp2, ds = ds[0], ds[1], ds[2:]
    coef, ts = ts[0], ts[1:]

    M1 = pow(cypher_text, exp1, p)
    M2 = pow(cypher_text, exp2, q)
    h = ((M1 - M2) * coef) % p
    m = M2 + q * h

    Ms = [pow(cypher_text, d, r) for d, r in zip(ds, rs)]
    Rs = list(itertools.accumulate([p, q] + rs, lambda x, y: x * y))
    for R, r, M, t in zip(Rs[1:], rs, Ms, ts):
        h = ((M - m) * t) % r
        m += R * h

    return m

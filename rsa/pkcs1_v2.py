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

"""Functions for PKCS#1 version 2 encryption and signing

This module implements certain functionality from PKCS#1 version 2. Main
documentation is RFC 8017: https://tools.ietf.org/html/rfc8017
"""

import os
from hmac import compare_digest

from . import common, transform, core, key, pkcs1
from ._compat import xor_bytes


def _constant_time_select(v: int, t: int, f: int) -> int:
    """Return t if v else f.

    v must be 0 or 1. (False and True are allowed)
    t and f are integer between 0 and 255.
    """
    v -= 1
    return (~v & t) | (v & f)


def mgf1(seed: bytes, length: int, hasher: str = "SHA-1") -> bytes:
    """
    MGF1 is a Mask Generation Function based on a hash function.

    A mask generation function takes an octet string of variable length and a
    desired output length as input, and outputs an octet string of the desired
    length. The plaintext-awareness of RSAES-OAEP relies on the random nature of
    the output of the mask generation function, which in turn relies on the
    random nature of the underlying hash.

    :param bytes seed: seed from which mask is generated, an octet string
    :param int length: intended length in octets of the mask, at most 2^32(hLen)
    :param str hasher: hash function (hLen denotes the length in octets of the hash
        function output)

    :return: mask, an octet string of length `length`
    :rtype: bytes

    :raise OverflowError: when `length` is too large for the specified `hasher`
    :raise ValueError: when specified `hasher` is invalid
    """

    try:
        hash_length = pkcs1.HASH_METHODS[hasher]().digest_size
    except KeyError as ex:
        raise ValueError(
            "Invalid `hasher` specified. Please select one of: {hash_list}".format(
                hash_list=", ".join(sorted(pkcs1.HASH_METHODS.keys()))
            )
        ) from ex

    # If l > 2^32(hLen), output "mask too long" and stop.
    if length > (2 ** 32 * hash_length):
        raise OverflowError(
            "Desired length should be at most 2**32 times the hasher's output "
            "length ({hash_length} for {hasher} function)".format(
                hash_length=hash_length,
                hasher=hasher,
            )
        )

    # Looping `counter` from 0 to ceil(l / hLen)-1, build `output` based on the
    # hashes formed by (`seed` + C), being `C` an octet string of length 4
    # generated by converting `counter` with the primitive I2OSP
    output = b"".join(
        pkcs1.compute_hash(
            seed + transform.int2bytes(counter, fill_size=4),
            method_name=hasher,
        )
        for counter in range(common.ceil_div(length, hash_length) + 1)
    )

    # Output the leading `length` octets of `output` as the octet string mask.
    return output[:length]


def _OAEP_encode(
    message: bytes, keylength: int, label, hash_method: str, mgf1_hash_method: str
) -> bytes:
    try:
        hasher = pkcs1.HASH_METHODS[hash_method](label)
    except KeyError:
        raise ValueError(
            "Invalid `hash_method` specified. Please select one of: {hash_list}".format(
                hash_list=", ".join(sorted(pkcs1.HASH_METHODS.keys()))
            )
        )
    hash_length = hasher.digest_size
    max_message_length = keylength - 2 * hash_length - 2
    message_length = len(message)
    if message_length > max_message_length:
        raise OverflowError(
            "message is too long; at most %s bytes, given %s bytes"
            % (max_message_length, len(message))
        )

    lhash = hasher.digest()
    ps = bytearray(keylength - message_length - 2 * hash_length - 2)
    db = (
        hasher.digest()
        + b"\0" * (keylength - message_length - 2 * hash_length - 2)
        + b"\x01"
        + message
    )

    seed = os.urandom(hash_length)
    db_mask = mgf1(seed, keylength - hash_length - 1, mgf1_hash_method)
    masked_db = xor_bytes(db, db_mask)

    seed_mask = mgf1(masked_db, hash_length, mgf1_hash_method)
    masked_seed = xor_bytes(seed, seed_mask)

    em = b"\x00" + masked_seed + masked_db
    return em


def encrypt_OAEP(
    message: bytes,
    pub_key: key.PublicKey,
    label: bytes = b"",
    hash_method: str = "SHA-1",
    mgf1_hash_method: str = None,
) -> bytes:
    """Encrypts the given message using PKCS#1 v2 RSA-OEAP.

    :param message: the message to encrypt.
    :param pub_key: the public key to encrypt with.
    :param label: optional RSA-OAEP label.
    :param hash_method: hash function to be used.  'SHA-1' (default),
        'SHA-256', 'SHA-384', and 'SHA-512' can be used.
    :param mgf1_hash_method: hash function to be used by MGF1 function.
        If it is None (default), *hash_method* is used.
    """
    # NOTE: Some hash method other than listed in the docstring can be used
    # for hash_method.  But the RFC 8017 recommends only them.
    if mgf1_hash_method is None:
        mgf1_hash_method = hash_method
    keylength = common.byte_size(pub_key.n)

    em = _OAEP_encode(message, keylength, label, hash_method, mgf1_hash_method)

    m = transform.bytes2int(em)
    encrypted = core.encrypt_int(m, pub_key.e, pub_key.n)
    c = transform.int2bytes(encrypted, keylength)

    return c


def decrypt_OAEP(
    crypto: bytes,
    priv_key: key.PrivateKey,
    label: bytes = b"",
    hash_method: str = "SHA-1",
    mgf1_hash_method: str = None,
) -> bytes:
    """Decrypts the givem crypto using PKCS#1 v2 RSA-OAEP.

    :param crypto: the crypto text as returned by :py:func:`rsa.encrypt`
    :param priv_key: the private key to decrypt with.
    :param label: optional RSA-OAEP label.
    :param hash_method: hash function to be used.  'SHA-1' (default),
        'SHA-256', 'SHA-384', and 'SHA-512' can be used.
    :param mgf1_hash_method: hash function to be used by MGF1 function.
        If it is None (default), *hash_method* is used.

    :raise rsa.pkcs1.DecryptionError: when the decryption fails. No details are given as
        to why the code thinks the decryption fails, as this would leak
        information about the private key.

    >>> import rsa
    >>> (pub_key, priv_key) = rsa.newkeys(512)

    It works with binary data:

    >>> crypto = encrypt_OAEP(b'hello', pub_key)
    >>> decrypt_OAEP(crypto, priv_key)
    b'hello'

    You can pass optional label data too:

    >>> crypto = encrypt_OAEP(b'hello', pub_key, label=b'world')
    >>> decrypt_OAEP(crypto, priv_key, label=b'world')
    b'hello'

    Altering the encrypted information will cause a
    :py:class:`rsa.pkcs1.DecryptionError`.

    >>> crypto = encrypt_OAEP(b'hello', pub_key)
    >>> crypto = crypto[0:5] + bytes([(ord(crypto[5:6])+1)%256]) + crypto[6:] # change a byte
    >>> decrypt_OAEP(crypto, priv_key)
    Traceback (most recent call last):
    ...
    rsa.pkcs1.DecryptionError: Decryption failed

    Changing label will also cause the error.

    >>> crypto = encrypt_OAEP(b'hello', pub_key, label=b'world')
    >>> decrypt_OAEP(crypto, priv_key, label=b'universe')
    Traceback (most recent call last):
    ...
    rsa.pkcs1.DecryptionError: Decryption failed
    """
    if mgf1_hash_method is None:
        mgf1_hash_method = hash_method

    # todo: Step 1: length checking
    k = common.byte_size(priv_key.n)
    if k != len(crypto):
        raise pkcs1.DecryptionError("Decryption failed")

    # Step 2: RSA Decryption
    c = transform.bytes2int(crypto)
    m = priv_key.blinded_decrypt(c)
    em = transform.int2bytes(m, k)

    # Step 3: EME-OAEP decoding
    try:
        hasher = pkcs1.HASH_METHODS[hash_method](label)
    except KeyError:
        raise ValueError(
            "Invalid `hash_method` specified. Please select one of: {hash_list}".format(
                hash_list=", ".join(sorted(pkcs1.HASH_METHODS.keys()))
            )
        )
    hash_length = hasher.digest_size
    lhash = hasher.digest()
    Y = em[0:1]
    masked_seed = em[1 : 1 + hash_length]
    masked_db = em[1 + hash_length :]

    seed_mask = mgf1(masked_db, hash_length, mgf1_hash_method)
    seed = xor_bytes(masked_seed, seed_mask)

    db_mask = mgf1(seed, k - hash_length - 1, mgf1_hash_method)
    db = xor_bytes(masked_db, db_mask)

    lhash_ = db[:hash_length]
    rest = db[hash_length:]

    # NOTE: Take care about timing attack.  See note in the RFC.
    hash_is_good = compare_digest(lhash, lhash_)

    index = invalid = 0
    looking_one = 1

    for i, c in enumerate(rest):
        iszero = c == 0
        isone = c == 1

        index = _constant_time_select(looking_one & isone, i, index)
        looking_one = _constant_time_select(isone, 0, looking_one)
        invalid = _constant_time_select(looking_one & ~iszero, 1, invalid)

    if invalid | looking_one | (not hash_is_good):
        raise pkcs1.DecryptionError("Decryption failed")

    return rest[index + 1 :]


__all__ = [
    "mgf1",
    "encrypt_OAEP",
    "decrypt_OAEP",
]

if __name__ == "__main__":
    print("Running doctests 1000x or until failure")
    import doctest

    for count in range(1000):
        (failures, tests) = doctest.testmod()
        if failures:
            break

        if count % 100 == 0 and count:
            print("%i times" % count)

    print("Doctests done")

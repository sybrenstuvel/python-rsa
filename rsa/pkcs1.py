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

"""Functions for PKCS#1 version 1.5 encryption and signing

This module implements certain functionality from PKCS#1 version 1.5. For a
very clear example, read http://www.di-mgt.com.au/rsa_alg.html#pkcs1schemes

At least 8 bytes of random padding is used when encrypting a message. This makes
these methods much more secure than the ones in the ``rsa`` module.

WARNING: this module leaks information when decryption fails. The exceptions
that are raised contain the Python traceback information, which can be used to
deduce where in the process the failure occurred. DO NOT PASS SUCH INFORMATION
to your users.
"""

__all__ = [
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "find_signature_hash",
    "sign_hash",
    "compute_hash"
]

import hashlib
import os
import typing
from hmac import compare_digest
import rsa.core as core_namespace
import rsa.helpers as helpers_namespace
import rsa.logic
import rsa.helpers.transform

if typing.TYPE_CHECKING:
    HashType = hashlib._Hash
    import key
else:
    HashType = typing.Any

# ASN.1 codes that describe the hash algorithm used.
HASH_ASN1: typing.Final[typing.Dict[str, bytes]] = {
    "MD5": b"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    "SHA-1": b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    "SHA-224": b"\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c",
    "SHA-256": b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    "SHA-384": b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
    "SHA-512": b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
    "SHA3-256": b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08\x05\x00\x04\x20",
    "SHA3-384": b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09\x05\x00\x04\x30",
    "SHA3-512": b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a\x05\x00\x04\x40",
}

HASH_METHODS: typing.Final[typing.Dict[str, typing.Callable[[], HashType]]] = {
    "MD5": hashlib.md5,
    "SHA-1": hashlib.sha1,
    "SHA-224": hashlib.sha224,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
    "SHA3-256": hashlib.sha3_256,
    "SHA3-384": hashlib.sha3_384,
    "SHA3-512": hashlib.sha3_512,
}
"""Hash methods supported by this library."""


def _pad_for_encryption(message: bytes, target_length: int) -> bytes:
    r"""Pads the message for encryption, returning the padded message.

    :return: 00 02 RANDOM_DATA 00 MESSAGE

    >>> block = _pad_for_encryption(b'hello', 16)
    >>> len(block)
    16
    >>> block[0:2]
    b'\x00\x02'
    >>> block[-6:]
    b'\x00hello'

    """

    max_msg_length = target_length - 11
    msg_length = len(message)

    if msg_length > max_msg_length:
        raise OverflowError(
            "%i bytes needed for message, but there is only"
            " space for %i" % (msg_length, max_msg_length)
        )

    # Get random padding
    padding = b""
    padding_length = target_length - msg_length - 3

    # We remove 0-bytes, so we'll end up with less padding than we've asked for,
    # so keep adding data until we're at the correct length.
    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)

        # Always read at least 8 bytes more than we need, and trim off the rest
        # after removing the 0-bytes. This increases the chance of getting
        # enough bytes, especially when needed_bytes is small
        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b"\x00", b"")
        padding = padding + new_padding[:needed_bytes]

    assert len(padding) == padding_length

    return b"".join([b"\x00\x02", padding, b"\x00", message])


def _pad_for_signing(message: bytes, target_length: int) -> bytes:
    r"""Pads the message for signing, returning the padded message.

    The padding is always a repetition of FF bytes.

    :return: 00 01 PADDING 00 MESSAGE

    >>> block = _pad_for_signing(b'hello', 16)
    >>> len(block)
    16
    >>> block[0:2]
    b'\x00\x01'
    >>> block[-6:]
    b'\x00hello'
    >>> block[2:-6]
    b'\xff\xff\xff\xff\xff\xff\xff\xff'

    """

    max_msg_length = target_length - 11
    mst_length = len(message)

    if mst_length > max_msg_length:
        raise OverflowError(
            "%i bytes needed for message, but there is only"
            " space for %i" % (mst_length, max_msg_length)
        )

    padding_length = target_length - mst_length - 3

    return b"".join([b"\x00\x01", padding_length * b"\xff", b"\x00", message])


def encrypt(message: bytes, pub_key: "key.PublicKey") -> bytes:
    """Encrypts the given message using PKCS#1 v1.5

    :param message: the message to encrypt. Must be a byte string no longer than
        ``k-11`` bytes, where ``k`` is the number of bytes needed to encode
        the ``n`` component of the public key.
    :param pub_key: the :py:class:`rsa.PublicKey` to encrypt with.
    :raise OverflowError: when the message is too large to fit in the padded
        block.

    >>> import rsa.helpers as inner_helpers_namespace
    >>> from rsa import key
    >>> public_key, private_key = key.new_keys(256)
    >>> message_inner = b'hello'
    >>> crypto = encrypt(message_inner, public_key)

    The crypto text should be just as long as the public key 'n' component:

    >>> len(crypto) == inner_helpers_namespace.byte_size(public_key.n)
    True

    """

    key_length = helpers_namespace.byte_size(pub_key.n)
    padded = _pad_for_encryption(message, key_length)

    payload = rsa.helpers.transform.bytes2int(padded)
    encrypted = rsa.logic.encrypt_int(payload, pub_key.e, pub_key.n)

    return rsa.helpers.transform.int2bytes(encrypted, key_length)


def decrypt(crypto: bytes, private_key: "key.PrivateKey") -> bytes:
    r"""Decrypts the given message using PKCS#1 v1.5

    The decryption is considered 'failed' when the resulting cleartext doesn't
    start with the bytes 00 02, or when the 00 byte between the padding and
    the message cannot be found.

    :param crypto: the crypto text as returned by :py:func:`rsa.encrypt`
    :param private_key: the :py:class:`rsa.PrivateKey` to decrypt with.
    :raise DecryptionError: when the decryption fails. No details are given as
        to why the code thinks the decryption fails, as this would leak
        information about the private key.


    >>> import rsa
    >>> pub_key, priv_key = rsa.new_keys(256)

    It works with strings:

    >>> crypto = rsa.encrypt(b'hello', pub_key)
    >>> rsa.decrypt(crypto, priv_key)
    b'hello'

    And with binary data:

    >>> crypto = rsa.encrypt(b'\x00\x00\x00\x00\x01', pub_key)
    >>> rsa.decrypt(crypto, priv_key)
    b'\x00\x00\x00\x00\x01'

    Altering the encrypted information will *likely* cause a
    :py:class:`rsa.pkcs1.DecryptionError`. If you want to be *sure*, use
    :py:func:`rsa.sign`.


    .. warning::

        Never display the stack trace of a
        :py:class:`rsa.pkcs1.DecryptionError` exception. It shows where in the
        code the exception occurred, and thus leaks information about the key.
        It's only a tiny bit of information, but every bit makes cracking the
        keys easier.


    """

    block_size = helpers_namespace.byte_size(private_key.n)
    encrypted = rsa.helpers.transform.bytes2int(crypto)
    decrypted = private_key.blinded_decrypt(encrypted)
    cleartext = rsa.helpers.transform.int2bytes(decrypted, block_size)

    # Detect leading zeroes in the crypto. These are not reflected in the
    # encrypted value (as leading zeroes do not influence the value of an
    # integer). This fixes CVE-2020-13757.
    if len(crypto) > block_size:
        # This is operating on public information, so doesn't need to be constant-time.
        raise core_namespace.DecryptionError("Decryption failed")

    # If we can't find the cleartext marker, decryption failed.
    cleartext_marker_bad = not compare_digest(cleartext[:2], b"\x00\x02")

    # Find the 00 separator between the padding and the message
    sep_idx = cleartext.find(b"\x00", 2)

    # sep_idx indicates the position of the `\x00` separator that separates the
    # padding from the actual message. The padding should be at least 8 bytes
    # long (see https://tools.ietf.org/html/rfc8017#section-7.2.2 step 3), which
    # means the separator should be at least at index 10 (because of the
    # `\x00\x02` marker that precedes it).
    sep_idx_bad = sep_idx < 10

    anything_bad = cleartext_marker_bad | sep_idx_bad
    if anything_bad:
        raise core_namespace.DecryptionError("Decryption failed")

    return cleartext[sep_idx + 1:]


def sign_hash(hash_value: bytes, private_key: "key.PrivateKey", hash_method: str) -> bytes:
    """Signs a precomputed hash with the private key.

    Signs the hash with the given key. This is known as a "detached signature",
    because the message itself isn't altered.

    :param hash_value: A precomputed hash to sign (ignores message).
    :param private_key: the :py:class:`rsa.PrivateKey` to sign with
    :param hash_method: the hash method used on the message. Use 'MD5', 'SHA-1',
        'SHA-224', SHA-256', 'SHA-384' or 'SHA-512'.
    :return: a message signature block.
    :raise OverflowError: if the private key is too small to contain the
        requested hash.

    """

    # Get the ASN1 code for this hash method
    if hash_method not in HASH_ASN1:
        raise ValueError("Invalid hash method: %s" % hash_method)
    asn1code = HASH_ASN1[hash_method]

    # Encrypt the hash with the private key
    cleartext = asn1code + hash_value
    key_length = helpers_namespace.byte_size(private_key.n)
    padded = _pad_for_signing(cleartext, key_length)

    payload = rsa.helpers.transform.bytes2int(padded)
    encrypted = private_key.blinded_decrypt(payload)

    return rsa.helpers.transform.int2bytes(encrypted, key_length)


def sign(message: bytes, private_key: "key.PrivateKey", hash_method: str) -> bytes:
    """Signs the message with the private key.

    Hashes the message, then signs the hash with the given key. This is known
    as a "detached signature", because the message itself isn't altered.

    :param message: the message to sign. Can be an 8-bit string or a file-like
        object. If ``message`` has a ``read()`` method, it is assumed to be a
        file-like object.
    :param private_key: the :py:class:`rsa.PrivateKey` to sign with
    :param hash_method: the hash method used on the message. Use 'MD5', 'SHA-1',
        'SHA-224', SHA-256', 'SHA-384' or 'SHA-512'.
    :return: a message signature block.
    :raise OverflowError: if the private key is too small to contain the
        requested hash.

    """

    msg_hash = compute_hash(message, hash_method)
    return sign_hash(msg_hash, private_key, hash_method)


def verify(message: bytes, signature: bytes, pub_key: "key.PublicKey") -> str:
    """Verifies that the signature matches the message.

    The hash method is detected automatically from the signature.

    :param message: the signed message. Can be an 8-bit string or a file-like
        object. If ``message`` has a ``read()`` method, it is assumed to be a
        file-like object.
    :param signature: the signature block, as created with :py:func:`rsa.sign`.
    :param pub_key: the :py:class:`rsa.PublicKey` of the person signing the message.
    :raise VerificationError: when the signature doesn't match the message.
    :returns: the name of the used hash.

    """

    key_length = helpers_namespace.byte_size(pub_key.n)
    if len(signature) != key_length:
        raise core_namespace.VerificationError("Verification failed")

    encrypted = rsa.helpers.transform.bytes2int(signature)
    decrypted = rsa.logic.encrypt_int(encrypted, pub_key.e, pub_key.n)
    clear_sig = rsa.helpers.transform.int2bytes(decrypted, key_length)

    # Get the hash method
    method_name = _find_method_hash(clear_sig)
    message_hash = compute_hash(message, method_name)

    # Reconstruct the expected padded hash
    cleartext = HASH_ASN1[method_name] + message_hash
    expected = _pad_for_signing(cleartext, key_length)

    # Compare with the signed one
    if expected != clear_sig:
        raise core_namespace.VerificationError("Verification failed")

    return method_name


def find_signature_hash(signature: bytes, pub_key: "key.PublicKey") -> str:
    """Returns the hash name detected from the signature.

    If you also want to verify the message, use :py:func:`rsa.verify()` instead.
    It also returns the name of the used hash.

    :param signature: the signature block, as created with :py:func:`rsa.sign`.
    :param pub_key: the :py:class:`rsa.PublicKey` of the person signing the message.
    :returns: the name of the used hash.
    """

    key_length = helpers_namespace.byte_size(pub_key.n)
    encrypted = rsa.helpers.transform.bytes2int(signature)
    decrypted = rsa.logic.decrypt_int(encrypted, pub_key.e, pub_key.n)
    clear_sig = rsa.helpers.transform.int2bytes(decrypted, key_length)

    return _find_method_hash(clear_sig)


def yield_fixed_blocks(infile: typing.BinaryIO, block_size: int) -> typing.Iterator[bytes]:
    """Generator, yields each block of ``block_size`` bytes in the input file.

    :param infile: file to read and separate in blocks.
    :param block_size: block size in bytes.
    :returns: a generator that yields the contents of each block
    """

    while True:
        block = infile.read(block_size)

        read_bytes = len(block)
        if read_bytes == 0:
            break

        yield block

        if read_bytes < block_size:
            break


def compute_hash(message: typing.Union[bytes, typing.BinaryIO], method_name: str) -> bytes:
    """Returns the message digest.

    :param message: the signed message. Can be an 8-bit string or a file-like
        object. If ``message`` has a ``read()`` method, it is assumed to be a
        file-like object.
    :param method_name: the hash method, must be a key of
        :py:const:`rsa.pkcs1.HASH_METHODS`.

    """

    if method_name not in HASH_METHODS:
        raise ValueError("Invalid hash method: %s" % method_name)

    method = HASH_METHODS[method_name]
    hasher = method()

    if isinstance(message, bytes):
        hasher.update(message)
    else:
        assert hasattr(message, "read") and hasattr(message.read, "__call__")
        # read as 1K blocks
        for block in yield_fixed_blocks(message, 1024):
            hasher.update(block)

    return hasher.digest()


def _find_method_hash(clear_sig: bytes) -> str:
    """Finds the hash method.

    :param clear_sig: full padded ASN1 and hash.
    :return: the used hash method.
    :raise VerificationFailed: when the hash method cannot be found
    """

    for (hash_name, asn1code) in HASH_ASN1.items():
        if asn1code in clear_sig:
            return hash_name

    raise core_namespace.VerificationError("Verification failed")


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

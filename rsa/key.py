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

"""RSA key generation code.

Create new keys with the newkeys() function. It will give you a PublicKey and a
PrivateKey object.

Loading and saving keys requires the pyasn1 module. This module is imported as
late as possible, such that other functionality will remain working in absence
of pyasn1.

.. note::

    Storing public and private keys via the `pickle` module is possible.
    However, it is insecure to load a key from an untrusted source.
    The pickle module is not secure against erroneous or maliciously
    constructed data. Never unpickle data received from an untrusted
    or unauthenticated source.

"""

import abc
import math
import threading
import typing
import warnings
import itertools

import rsa.prime
import rsa.pem
import rsa.common
import rsa.randnum
import rsa.core


DEFAULT_EXPONENT = 65537


T = typing.TypeVar("T", bound="AbstractKey")


class AbstractKey(metaclass=abc.ABCMeta):
    """Abstract superclass for private and public keys."""

    __slots__ = ("n", "e", "blindfac", "blindfac_inverse", "mutex")

    def __init__(self, n: int, e: int) -> None:
        self.n = n
        self.e = e

        # These will be computed properly on the first call to blind().
        self.blindfac = self.blindfac_inverse = -1

        # Used to protect updates to the blinding factor in multi-threaded
        # environments.
        self.mutex = threading.Lock()

    @classmethod
    @abc.abstractmethod
    def _load_pkcs1_pem(cls: typing.Type[T], keyfile: bytes) -> T:
        """Loads a key in PKCS#1 PEM format, implement in a subclass.

        :param keyfile: contents of a PEM-encoded file that contains
            the public key.
        :type keyfile: bytes

        :return: the loaded key
        :rtype: AbstractKey
        """

    @classmethod
    @abc.abstractmethod
    def _load_pkcs1_der(cls: typing.Type[T], keyfile: bytes) -> T:
        """Loads a key in PKCS#1 PEM format, implement in a subclass.

        :param keyfile: contents of a DER-encoded file that contains
            the public key.
        :type keyfile: bytes

        :return: the loaded key
        :rtype: AbstractKey
        """

    @abc.abstractmethod
    def _save_pkcs1_pem(self) -> bytes:
        """Saves the key in PKCS#1 PEM format, implement in a subclass.

        :returns: the PEM-encoded key.
        :rtype: bytes
        """

    @abc.abstractmethod
    def _save_pkcs1_der(self) -> bytes:
        """Saves the key in PKCS#1 DER format, implement in a subclass.

        :returns: the DER-encoded key.
        :rtype: bytes
        """

    @classmethod
    def load_pkcs1(cls: typing.Type[T], keyfile: bytes, format: str = "PEM") -> T:
        """Loads a key in PKCS#1 DER or PEM format.

        :param keyfile: contents of a DER- or PEM-encoded file that contains
            the key.
        :type keyfile: bytes
        :param format: the format of the file to load; 'PEM' or 'DER'
        :type format: str

        :return: the loaded key
        :rtype: AbstractKey
        """

        methods = {
            "PEM": cls._load_pkcs1_pem,
            "DER": cls._load_pkcs1_der,
        }

        method = cls._assert_format_exists(format, methods)
        return method(keyfile)

    @staticmethod
    def _assert_format_exists(
        file_format: str, methods: typing.Mapping[str, typing.Callable]
    ) -> typing.Callable:
        """Checks whether the given file format exists in 'methods'."""

        try:
            return methods[file_format]
        except KeyError as ex:
            formats = ", ".join(sorted(methods.keys()))
            raise ValueError(
                "Unsupported format: %r, try one of %s" % (file_format, formats)
            ) from ex

    def save_pkcs1(self, format: str = "PEM") -> bytes:
        """Saves the key in PKCS#1 DER or PEM format.

        :param format: the format to save; 'PEM' or 'DER'
        :type format: str
        :returns: the DER- or PEM-encoded key.
        :rtype: bytes
        """

        methods = {
            "PEM": self._save_pkcs1_pem,
            "DER": self._save_pkcs1_der,
        }

        method = self._assert_format_exists(format, methods)
        return method()

    def blind(self, message: int) -> typing.Tuple[int, int]:
        """Performs blinding on the message.

        :param message: the message, as integer, to blind.
        :param r: the random number to blind with.
        :return: tuple (the blinded message, the inverse of the used blinding factor)

        The blinding is such that message = unblind(decrypt(blind(encrypt(message))).

        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        """
        blindfac, blindfac_inverse = self._update_blinding_factor()
        blinded = (message * pow(blindfac, self.e, self.n)) % self.n
        return blinded, blindfac_inverse

    def unblind(self, blinded: int, blindfac_inverse: int) -> int:
        """Performs blinding on the message using random number 'blindfac_inverse'.

        :param blinded: the blinded message, as integer, to unblind.
        :param blindfac: the factor to unblind with.
        :return: the original message.

        The blinding is such that message = unblind(decrypt(blind(encrypt(message))).

        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        """
        return (blindfac_inverse * blinded) % self.n

    def _initial_blinding_factor(self) -> int:
        for _ in range(1000):
            blind_r = rsa.randnum.randint(self.n - 1)
            if rsa.prime.are_relatively_prime(self.n, blind_r):
                return blind_r
        raise RuntimeError("unable to find blinding factor")

    def _update_blinding_factor(self) -> typing.Tuple[int, int]:
        """Update blinding factors.

        Computing a blinding factor is expensive, so instead this function
        does this once, then updates the blinding factor as per section 9
        of 'A Timing Attack against RSA with the Chinese Remainder Theorem'
        by Werner Schindler.
        See https://tls.mbed.org/public/WSchindler-RSA_Timing_Attack.pdf

        :return: the new blinding factor and its inverse.
        """

        with self.mutex:
            if self.blindfac < 0:
                # Compute initial blinding factor, which is rather slow to do.
                self.blindfac = self._initial_blinding_factor()
                self.blindfac_inverse = rsa.common.inverse(self.blindfac, self.n)
            else:
                # Reuse previous blinding factor.
                self.blindfac = pow(self.blindfac, 2, self.n)
                self.blindfac_inverse = pow(self.blindfac_inverse, 2, self.n)

            return self.blindfac, self.blindfac_inverse


class PublicKey(AbstractKey):
    """Represents a public RSA key.

    This key is also known as the 'encryption key'. It contains the 'n' and 'e'
    values.

    Supports attributes as well as dictionary-like access. Attribute access is
    faster, though.

    >>> PublicKey(5, 3)
    PublicKey(5, 3)

    >>> key = PublicKey(5, 3)
    >>> key.n
    5
    >>> key['n']
    5
    >>> key.e
    3
    >>> key['e']
    3

    """

    __slots__ = ()

    def __getitem__(self, key: str) -> int:
        return getattr(self, key)

    def __repr__(self) -> str:
        return "PublicKey(%i, %i)" % (self.n, self.e)

    def __getstate__(self) -> typing.Tuple[int, int]:
        """Returns the key as tuple for pickling."""
        return self.n, self.e

    def __setstate__(self, state: typing.Tuple[int, int]) -> None:
        """Sets the key from tuple."""
        self.n, self.e = state
        AbstractKey.__init__(self, self.n, self.e)

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False

        if not isinstance(other, PublicKey):
            return False

        return self.n == other.n and self.e == other.e

    def __ne__(self, other: typing.Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash((self.n, self.e))

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> "PublicKey":
        """Loads a key in PKCS#1 DER format.

        :param keyfile: contents of a DER-encoded file that contains the public
            key.
        :return: a PublicKey object

        First let's construct a DER encoded key:

        >>> import base64
        >>> b64der = 'MAwCBQCNGmYtAgMBAAE='
        >>> der = base64.standard_b64decode(b64der)

        This loads the file:

        >>> PublicKey._load_pkcs1_der(der)
        PublicKey(2367317549, 65537)

        """

        from pyasn1.codec.der import decoder
        from rsa.asn1 import AsnPubKey

        (priv, _) = decoder.decode(keyfile, asn1Spec=AsnPubKey())
        return cls(n=int(priv["modulus"]), e=int(priv["publicExponent"]))

    def _save_pkcs1_der(self) -> bytes:
        """Saves the public key in PKCS#1 DER format.

        :returns: the DER-encoded public key.
        :rtype: bytes
        """

        from pyasn1.codec.der import encoder
        from rsa.asn1 import AsnPubKey

        # Create the ASN object
        asn_key = AsnPubKey()
        asn_key.setComponentByName("modulus", self.n)
        asn_key.setComponentByName("publicExponent", self.e)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile: bytes) -> "PublicKey":
        """Loads a PKCS#1 PEM-encoded public key file.

        The contents of the file before the "-----BEGIN RSA PUBLIC KEY-----" and
        after the "-----END RSA PUBLIC KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the public
            key.
        :return: a PublicKey object
        """

        der = rsa.pem.load_pem(keyfile, "RSA PUBLIC KEY")
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self) -> bytes:
        """Saves a PKCS#1 PEM-encoded public key file.

        :return: contents of a PEM-encoded file that contains the public key.
        :rtype: bytes
        """

        der = self._save_pkcs1_der()
        return rsa.pem.save_pem(der, "RSA PUBLIC KEY")

    @classmethod
    def load_pkcs1_openssl_pem(cls, keyfile: bytes) -> "PublicKey":
        """Loads a PKCS#1.5 PEM-encoded public key file from OpenSSL.

        These files can be recognised in that they start with BEGIN PUBLIC KEY
        rather than BEGIN RSA PUBLIC KEY.

        The contents of the file before the "-----BEGIN PUBLIC KEY-----" and
        after the "-----END PUBLIC KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the public
            key, from OpenSSL.
        :type keyfile: bytes
        :return: a PublicKey object
        """

        der = rsa.pem.load_pem(keyfile, "PUBLIC KEY")
        return cls.load_pkcs1_openssl_der(der)

    @classmethod
    def load_pkcs1_openssl_der(cls, keyfile: bytes) -> "PublicKey":
        """Loads a PKCS#1 DER-encoded public key file from OpenSSL.

        :param keyfile: contents of a DER-encoded file that contains the public
            key, from OpenSSL.
        :return: a PublicKey object
        """

        from rsa.asn1 import OpenSSLPubKey
        from pyasn1.codec.der import decoder
        from pyasn1.type import univ

        (keyinfo, _) = decoder.decode(keyfile, asn1Spec=OpenSSLPubKey())

        if keyinfo["header"]["oid"] != univ.ObjectIdentifier("1.2.840.113549.1.1.1"):
            raise TypeError("This is not a DER-encoded OpenSSL-compatible public key")

        return cls._load_pkcs1_der(keyinfo["key"][1:])


class PrivateKey(AbstractKey):
    """Represents a private RSA key.

    This key is also known as the 'decryption key'. It contains the 'n', 'e',
    'd', 'p', 'q' and other values. For example ,in the case of multiprime RSA,
    it additionally contains the lists 'rs', 'ds', and 'ts' which contain the
    factors, exponents, and coefficients for the other primes.

    Supports attributes as well as dictionary-like access. Attribute access is
    faster, though.

    >>> PrivateKey(3247, 65537, 833, 191, 17)
    PrivateKey(3247, 65537, 833, 191, 17)

    exp1, exp2 and coef will be calculated:

    >>> pk = PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)
    >>> pk.exp1
    55063
    >>> pk.exp2
    10095
    >>> pk.coef
    50797

    """

    __slots__ = ("d", "p", "q", "exp1", "exp2", "coef", "rs", "ds", "ts")

    def __init__(
        self,
        n: int,
        e: int,
        d: int,
        p: int,
        q: int,
        rs: typing.Optional[typing.List[int]] = None,
    ) -> None:
        rs = [] if rs is None else rs

        AbstractKey.__init__(self, n, e)
        self.d = d
        self.p = p
        self.q = q

        # Calculate exponents and coefficient.
        self.exp1 = int(d % (p - 1))
        self.exp2 = int(d % (q - 1))
        self.coef = rsa.common.inverse(q, p)

        # Calculate other primes' exponents and coefficients.
        self.rs = rs
        self.ds = [int(d % (r - 1)) for r in rs]
        Rs = list(itertools.accumulate([p, q] + rs, lambda x, y: x*y))
        self.ts = [pow(R, -1, r) for R, r in zip(Rs[1:], rs)]

    def __getitem__(self, key: str) -> int:
        return getattr(self, key)

    def __repr__(self) -> str:
        if self.rs:
            return "PrivateKey(%i, %i, %i, %i, %i, %s)" % (
                self.n,
                self.e,
                self.d,
                self.p,
                self.q,
                self.rs,
            )
        else:
            return "PrivateKey(%i, %i, %i, %i, %i)" % (
                self.n,
                self.e,
                self.d,
                self.p,
                self.q,
            )

    def __getstate__(self) -> typing.Tuple:
        """Returns the key as tuple for pickling."""
        if self.rs:
            return (
                self.n,
                self.e,
                self.d,
                self.p,
                self.q,
                self.exp1,
                self.exp2,
                self.coef,
                self.rs,
                self.ds,
                self.ts,
            )
        else:
            return self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef

    def __setstate__(self, state: typing.Tuple) -> None:
        """Sets the key from tuple."""
        if len(state) != 8:
            (
                self.n,
                self.e,
                self.d,
                self.p,
                self.q,
                self.exp1,
                self.exp2,
                self.coef,
                self.rs,
                self.ds,
                self.ts,
             ) = state
        else:
            self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef = state
            self.rs = self.ds = self.ts = []
        AbstractKey.__init__(self, self.n, self.e)

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False

        if not isinstance(other, PrivateKey):
            return False

        return all([getattr(self, k) == getattr(other, k) for k in self.__slots__])

    def __ne__(self, other: typing.Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        if self.rs:
            return hash((
                self.n,
                self.e,
                self.d,
                self.p,
                self.q,
                self.exp1,
                self.exp2,
                self.coef,
                *self.rs,
                *self.ds,
                *self.ts
            ))
        else:
            return hash((self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef))

    def blinded_decrypt(self, encrypted: int) -> int:
        """Decrypts the message using blinding to prevent side-channel attacks.

        :param encrypted: the encrypted message
        :type encrypted: int

        :returns: the decrypted message
        :rtype: int
        """

        # Blinding and un-blinding should be using the same factor
        blinded, blindfac_inverse = self.blind(encrypted)
        decrypted = rsa.core.decrypt_int_fast(
            blinded,
            [self.p, self.q] + self.rs,
            [self.exp1, self.exp2] + self.ds,
            [self.coef] + self.ts,
        )
        return self.unblind(decrypted, blindfac_inverse)

    @classmethod
    def _load_pkcs1_der(cls, keyfile: bytes) -> "PrivateKey":
        """Loads a key in PKCS#1 DER format.

        :param keyfile: contents of a DER-encoded file that contains the private
            key.
        :type keyfile: bytes
        :return: a PrivateKey object

        First let's construct a DER encoded key:

        >>> import base64
        >>> b64der = 'MC4CAQACBQDeKYlRAgMBAAECBQDHn4npAgMA/icCAwDfxwIDANcXAgInbwIDAMZt'
        >>> der = base64.standard_b64decode(b64der)

        This loads the file:

        >>> PrivateKey._load_pkcs1_der(der)
        PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)

        """

        from pyasn1.codec.der import decoder

        (priv, _) = decoder.decode(keyfile)

        # ASN.1 contents of DER encoded private key:
        #
        # RSAPrivateKey ::= SEQUENCE {
        #     version           Version,
        #     modulus           INTEGER,  -- n
        #     publicExponent    INTEGER,  -- e
        #     privateExponent   INTEGER,  -- d
        #     prime1            INTEGER,  -- p
        #     prime2            INTEGER,  -- q
        #     exponent1         INTEGER,  -- d mod (p-1)
        #     exponent2         INTEGER,  -- d mod (q-1)
        #     coefficient       INTEGER,  -- (inverse of q) mod p
        #     otherPrimeInfos   OtherPrimeInfos OPTIONAL
        # }

        if priv[0] != 0:
            raise ValueError("Unable to read this file, version %s != 0" % priv[0])

        n, e, d, p, q = map(int, priv[1:6])
        exp1, exp2, coef = map(int, priv[6:9])
        rs = map(int, priv[9::3])
        ds = map(int, priv[10::3])
        ts = map(int, priv[11::3])

        key = cls(n, e, d, p, q, list(rs))

        if (key.exp1, key.exp2, key.coef, key.rs, key.ds, key.ts) != (exp1, exp2, coef, rs, ds, ts):
            warnings.warn(
                "You have provided a malformed keyfile. Either the exponents "
                "or the coefficient are incorrect. Using the correct values "
                "instead.",
                UserWarning,
            )

        return key

    def _save_pkcs1_der(self) -> bytes:
        """Saves the private key in PKCS#1 DER format.

        :returns: the DER-encoded private key.
        :rtype: bytes
        """

        from pyasn1.type import univ, namedtype
        from pyasn1.codec.der import encoder

        other_fields = [
            (
                namedtype.NamedType("prime%d" % (i + 3), univ.Integer()),
                namedtype.NamedType("exponent%d" % (i + 3), univ.Integer()),
                namedtype.NamedType("coefficient%d" % (i + 3), univ.Integer()),
            ) for i in range(len(self.rs))
        ]
        
        class AsnPrivKey(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType("version", univ.Integer()),
                namedtype.NamedType("modulus", univ.Integer()),
                namedtype.NamedType("publicExponent", univ.Integer()),
                namedtype.NamedType("privateExponent", univ.Integer()),
                namedtype.NamedType("prime1", univ.Integer()),
                namedtype.NamedType("prime2", univ.Integer()),
                namedtype.NamedType("exponent1", univ.Integer()),
                namedtype.NamedType("exponent2", univ.Integer()),
                namedtype.NamedType("coefficient", univ.Integer()),
                *list(itertools.chain(*other_fields))
            )

        # Create the ASN object
        asn_key = AsnPrivKey()
        asn_key.setComponentByName("version", 0)
        asn_key.setComponentByName("modulus", self.n)
        asn_key.setComponentByName("publicExponent", self.e)
        asn_key.setComponentByName("privateExponent", self.d)
        asn_key.setComponentByName("prime1", self.p)
        asn_key.setComponentByName("prime2", self.q)
        asn_key.setComponentByName("exponent1", self.exp1)
        asn_key.setComponentByName("exponent2", self.exp2)
        asn_key.setComponentByName("coefficient", self.coef)
        for i, (r, d, t) in enumerate(zip(self.rs, self.ds, self.ts), start=3):
            asn_key.setComponentByName("prime%d" % i, r)
            asn_key.setComponentByName("exponent%d" % i, d)
            asn_key.setComponentByName("coefficient%d" % i, t)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile: bytes) -> "PrivateKey":
        """Loads a PKCS#1 PEM-encoded private key file.

        The contents of the file before the "-----BEGIN RSA PRIVATE KEY-----" and
        after the "-----END RSA PRIVATE KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the private
            key.
        :type keyfile: bytes
        :return: a PrivateKey object
        """

        der = rsa.pem.load_pem(keyfile, b"RSA PRIVATE KEY")
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self) -> bytes:
        """Saves a PKCS#1 PEM-encoded private key file.

        :return: contents of a PEM-encoded file that contains the private key.
        :rtype: bytes
        """

        der = self._save_pkcs1_der()
        return rsa.pem.save_pem(der, b"RSA PRIVATE KEY")


def find_primes(
    nbits: int,
    getprime_func: typing.Callable[[int], int] = rsa.prime.getprime,
    accurate: bool = True,
    nprimes: int = 2,
) -> typing.List[int]:
    """Returns a list of different primes with nbits divided evenly among them.

    :param nbits: the number of bits for the primes to sum to.
    :param getprime_func: the getprime function, defaults to
        :py:func:`rsa.prime.getprime`.
    :param accurate: whether to enable accurate mode or not.
    :returns: list of primes in descending order.

    """
    if nprimes == 2:
        return list(find_p_q(nbits // 2, getprime_func, accurate))

    quo, rem = divmod(nbits, nprimes)
    factor_lengths = [quo + 1]*rem + [quo] * (nprimes - rem)

    while True:
        primes = [getprime_func(length) for length in factor_lengths]
        if len(set(primes)) == len(primes):
            break

    return list(reversed(sorted(primes)))


def find_p_q(
    nbits: int,
    getprime_func: typing.Callable[[int], int] = rsa.prime.getprime_FIPS,
    accurate: bool = True,
) -> typing.Tuple[int, int]:
    """Returns a tuple of two different primes of nbits bits each.

    The resulting p * q has exactly 2 * nbits bits, and the returned p and q
    will not be equal.

    :param nbits: the number of bits in each of p and q.
    :param getprime_func: the getprime function, defaults to
        :py:func:`rsa.prime.getprime`.#TODO:update

        *Introduced in Python-RSA 3.1*

    :param accurate: whether to enable accurate mode or not.
    :returns: (p, q), where p > q

    >>> (p, q) = find_p_q(128)
    >>> from rsa import common
    >>> common.bit_size(p * q)
    256

    When not in accurate mode, the number of bits can be slightly less

    >>> (p, q) = find_p_q(128, accurate=False)
    >>> from rsa import common
    >>> common.bit_size(p * q) <= 256
    True
    >>> common.bit_size(p * q) > 240
    True

    """

    total_bits = nbits * 2    

    def is_acceptable(p: int, q: int) -> bool:
        """Returns True iff p and q are acceptable:
        
        NIST.FIPS.186-4 acceptance criteria:
        - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf#%5B%7B%22num%22%3A127%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C223%2C0%5D
        - p and q are in the range [2**(nbits+0.5),2**nbits]
        - abs(p-q)>2**(nbits-100)
        - the strong prime requirements are ignored
          - http://people.csail.mit.edu/rivest/RivestSilverman-AreStrongPrimesNeededForRSA.pdf
          - (the paper argues they're not needed)
        - provable prime requirements for smaller key sizes are ignored
        """
        #end=2**nbits
        #start=rsa.prime._bigint_divide_by_sqrt_2(end)
        #if not start<=p<end:return False
        #if not start<=q<end:return False
        # these are guaranteed by the getprime_func
        # alternate getprime_func can give values that do not comply
        if not abs(p-q)>2**(nbits-100):return False
        found_size = rsa.common.bit_size(p * q)

        #this should be guaranteed by the previous range checks
        return found_size==total_bits or not accurate
    
    while 1:
        # Keep generating primes if there's a failure.
        p = getprime_func(nbits)
        q = getprime_func(nbits)
        #note:failure has negligible probability
        if is_acceptable(p, q):break

    # We want p > q as described on
    # http://www.di-mgt.com.au/rsa_alg.html#crt
    return max(p, q), min(p, q)


def calculate_keys_custom_exponent(
    p: int,
    q: int,
    exponent: int,
    rs: typing.Optional[typing.List[int]] = None,
) -> typing.Tuple[int, int]:
    """Calculates an encryption and a decryption key given p, q and an exponent,
    and returns them as a tuple (e, d)

    :param p: the first large prime
    :param q: the second large prime
    :param exponent: the exponent for the key; only change this if you know
        what you're doing, as the exponent influences how difficult your
        private key can be cracked. A very common choice for e is 65537.
    :type exponent: int
    :param rs: the list of other large primes

    """

    phi_n = math.prod([x - 1 for x in [p, q] + ([] if rs is None else rs)])

    try:
        d = rsa.common.inverse(exponent, phi_n)
    except rsa.common.NotRelativePrimeError as ex:
        raise rsa.common.NotRelativePrimeError(
            exponent,
            phi_n,
            ex.d,
            msg="e (%d) and phi_n (%d) are not relatively prime (divider=%i)"
            % (exponent, phi_n, ex.d),
        ) from ex

    if (exponent * d) % phi_n != 1:
        raise ValueError(
            "e (%d) and d (%d) are not mult. inv. modulo " "phi_n (%d)" % (exponent, d, phi_n)
        )

    return exponent, d


def calculate_keys(p: int, q: int) -> typing.Tuple[int, int]:
    """Calculates an encryption and a decryption key given p and q, and
    returns them as a tuple (e, d)

    :param p: the first large prime
    :param q: the second large prime

    :return: tuple (e, d) with the encryption and decryption exponents.
    """

    return calculate_keys_custom_exponent(p, q, DEFAULT_EXPONENT)


def gen_keys(
    nbits: int,
    getprime_func: typing.Callable[[int], int],
    accurate: bool = True,
    exponent: int = DEFAULT_EXPONENT,
    nprimes: int = 2,
) -> typing.Tuple:
    """Generate RSA keys of nbits bits. Returns (p, q, e, d) or (p, q, e, d, rs).

    Note: this can take a long time, depending on the key size.

    :param nbits: the total number of bits in ``p`` and ``q``. Both ``p`` and
        ``q`` will use ``nbits/2`` bits.
    :param getprime_func: either :py:func:`rsa.prime.getprime` or a function
        with similar signature.
    :param exponent: the exponent for the key; only change this if you know
        what you're doing, as the exponent influences how difficult your
        private key can be cracked. A very common choice for e is 65537.
    :type exponent: int
    :param nprimes: the number of prime factors comprising the modulus.
    """

    # Regenerate prime values, until calculate_keys_custom_exponent doesn't raise a
    # ValueError.
    while True:
        primes = find_primes(nbits, getprime_func, accurate, nprimes)
        p, q, rs = primes[0], primes[1], primes[2:]
        try:
            (e, d) = calculate_keys_custom_exponent(p, q, exponent=exponent, rs=rs)
            break
        except ValueError:
            pass

    if rs:
        return p, q, e, d, rs
    else:
        return p, q, e, d


def newkeys(
    nbits: int,
    accurate: bool = True,
    poolsize: int = 1,
    exponent: int = DEFAULT_EXPONENT,
    nprimes: int = 2,
) -> typing.Tuple[PublicKey, PrivateKey]:
    """Generates public and private keys, and returns them as (pub, priv).

    The public key is also known as the 'encryption key', and is a
    :py:class:`rsa.PublicKey` object. The private key is also known as the
    'decryption key' and is a :py:class:`rsa.PrivateKey` object.

    :param nbits: the number of bits required to store the modulus ``n``.
    :param accurate: when True, ``n`` will have exactly the number of bits you
        asked for. However, this makes key generation much slower. When False,
        `n`` may have slightly less bits.
    :param poolsize: the number of processes to use to generate the prime
        numbers. If set to a number > 1, a parallel algorithm will be used.
        This requires Python 2.6 or newer.
    :param exponent: the exponent for the key; only change this if you know
        what you're doing, as the exponent influences how difficult your
        private key can be cracked. A very common choice for e is 65537.
    :type exponent: int
    :param nprimes: the number of prime factors comprising the modulus.

    :returns: a tuple (:py:class:`rsa.PublicKey`, :py:class:`rsa.PrivateKey`)

    The ``poolsize`` parameter was added in *Python-RSA 3.1* and requires
    Python 2.6 or newer.

    """

    if nbits < 16:
        raise ValueError("Key too small")

    if poolsize < 1:
        raise ValueError("Pool size (%i) should be >= 1" % poolsize)

    if nprimes < 2:
        raise ValueError("Number of primes (%i) should be >= 2" % nprimes)

    # Determine which getprime function to use
    if poolsize > 1:
        from rsa import parallel

        def getprime_func(nbits: int) -> int:
            return parallel.getprime(nbits, poolsize=poolsize)

    else:
        getprime_func = rsa.prime.getprime

    # Generate the key components
    result = gen_keys(nbits, getprime_func, accurate=accurate, exponent=exponent, nprimes=nprimes)
    if len(result) == 4:
        p, q, e, d = result
        rs = []
    else:
        p, q, e, d, rs = result

    # Create the key objects
    n = math.prod([p, q] + rs)

    return (PublicKey(n, e), PrivateKey(n, e, d, p, q, rs))


__all__ = ["PublicKey", "PrivateKey", "newkeys"]

if __name__ == "__main__":
    import doctest

    try:
        for count in range(100):
            (failures, tests) = doctest.testmod()
            if failures:
                break

            if (count % 10 == 0 and count) or count == 1:
                print("%i times" % count)
    except KeyboardInterrupt:
        print("Aborted")
    else:
        print("Doctests done")

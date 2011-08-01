Reference
==================================================

Functions
--------------------------------------------------

.. autofunction:: rsa.encrypt

.. autofunction:: rsa.decrypt

.. autofunction:: rsa.sign

.. autofunction:: rsa.verify

.. autofunction:: rsa.newkeys(keysize)

.. autofunction:: rsa.bigfile.encrypt_bigfile

.. autofunction:: rsa.bigfile.decrypt_bigfile


Classes
--------------------------------------------------

.. autoclass:: rsa.PublicKey
    :members:
    :inherited-members:

.. autoclass:: rsa.PrivateKey
    :members:
    :inherited-members:

Exceptions
--------------------------------------------------

.. autoclass:: rsa.pkcs1.CryptoError(Exception)

.. autoclass:: rsa.pkcs1.DecryptionError(CryptoError)

.. autoclass:: rsa.pkcs1.VerificationError(CryptoError)


.. index:: VARBLOCK (file format)

The VARBLOCK file format
--------------------------------------------------

The VARBLOCK file format allows us to encrypt files that are larger
than the RSA key. The format is as follows; || denotes byte string
concatenation::

 VARBLOCK := VERSION || BLOCK || BLOCK || ...

 VERSION := 1

 BLOCK := LENGTH || DATA

 LENGTH := varint-encoded length of the followng data, in bytes

 DATA := the data to store in the block

The varint-format was taken from Google's Protobuf_, and allows us to
efficiently encode an arbitrarily long integer.

.. _Protobuf:
    http://code.google.com/apis/protocolbuffers/docs/encoding.html#varints


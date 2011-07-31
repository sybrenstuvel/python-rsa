Reference
==================================================

Functions
--------------------------------------------------

.. autofunction:: rsa.encrypt

.. autofunction:: rsa.decrypt

.. autofunction:: rsa.sign

.. autofunction:: rsa.verify

.. autofunction:: rsa.newkeys(keysize)

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




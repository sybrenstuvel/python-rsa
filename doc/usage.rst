Usage
==================================================

This section describes the usage of the Python-RSA module.

Before you can use RSA you need keys. You will receive a private key
and a public key.

.. note::

    The private key is called *private* for a reason. Never share this
    key with anyone.

The public key is used for encypting a message such that it can only
be read by the owner of the private key. As such it's also referred to
as the *encryption key*. Decrypting a message can only be done using
the private key, hence it's also called the *decryption key*.

The private key is used for signing a message. With this signature and
the public key, the receiver can verifying that a message was signed
by the owner of the private key, and that the message was not modified
after signing.

Generating keys
--------------------------------------------------

You can use the :py:func:`rsa.newkeys` function to create a keypair:

    >>> (pubkey, privkey) = rsa.newkeys(512)

Alternatively you can use :py:meth:`rsa.PrivateKey.load_pkcs1` and
:py:meth:`rsa.PublicKey.load_pkcs1` to load keys from a file:

    >>> with open('private.pem') as privatefile:
    ...     keydata = privatefile.read()
    >>> pubkey = rsa.PrivateKey.load_pkcs1(keydata)

Generating a keypair may take a long time, depending on the number of
bits required. The number of bits determines the cryptographic
strength of the key, as well as the size of the message you can
encrypt. If you don't mind having a slightly smaller key than you
requested, you can pass ``accurate=False`` to speed up the key
generation process.

These are some timings from my netbook (Linux 2.6, 1.6 GHz Intel Atom
N270 CPU, 2 GB RAM):

+----------------+------------------+
| Keysize (bits) | Time to generate |
+================+==================+
| 32             | 0.01 sec.        |
+----------------+------------------+
| 64             | 0.03 sec.        |
+----------------+------------------+
| 96             | 0.04 sec.        |
+----------------+------------------+
| 128            | 0.08 sec.        |
+----------------+------------------+
| 256            | 0.27 sec.        |
+----------------+------------------+
| 384            | 0.93 sec.        |
+----------------+------------------+
| 512            | 1.21 sec.        |
+----------------+------------------+
| 1024           | 7.93 sec.        |
+----------------+------------------+
| 2048           | 132.97 sec.      |
+----------------+------------------+


Encryption and decryption
--------------------------------------------------

To encrypt or decrypt a message, use :py:func:`rsa.encrypt` resp.
:py:func:`rsa.decrypt`. Let's say that Alice wants to send a message
that only Bob can read.

#. Bob generates a keypair, and gives the public key to Alice. This is
   done such that Alice knows for sure that the key is really Bob's
   (for example by handing over a USB stick that contains the key).

    >>> (bob_pub, bob_priv) = rsa.newkeys(512)

#. Alice writes a message

    >>> message = 'hello Bob!'

#. Alice encrypts the message using Bob's public key, and sends the
   encrypted message.

    >>> cryto = rsa.encrypt(message, bob_pub)

#. Bob receives the message, and decrypts it with his private key.

    >>> message = rsa.decrypt(crypto, bob_priv)
    >>> print message
    hello Bob!

Since Bob kept his private key *private*, Alice can be sure that he is
the only one who can read the message.

.. note::

    Bob does *not* know for sure that it was Alice that sent the
    message, since she didn't sign it.


Low-level operations
++++++++++++++++++++++++++++++

The core RSA algorithm operates on large integers. These operations
are considered low-level and are supported by the
:py:func:`rsa.core.encrypt_int` and :py:func:`rsa.core.decrypt_int`
functions.

Signing and verification
--------------------------------------------------

You can create a detached signature for a message using the
:py:func:`rsa.sign` function:

    >>> (pubkey, privkey) = rsa.newkeys(512)
    >>> message = 'Go left at the blue tree'
    >>> signature = rsa.sign(message, privkey, 'SHA-1')
    
This hashes the message using SHA-1. Other hash methods are also
possible, check the :py:func:`rsa.sign` function documentation for
details. The hash is then signed with the private key.

In order to verify the signature, use the :py:func:`rsa.verify`
function.

    >>> message = 'Go left at the blue tree'
    >>> rsa.verify(message, signature, pubkey)

Modify the message, and the signature is no longer valid and a
:py:class:`rsa.pkcs1.VerificationError` is thrown:

    >>> message = 'Go right at the blue tree'
    >>> rsa.verify(message, signature, pubkey)
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "/home/sybren/workspace/python-rsa/rsa/pkcs1.py", line 289, in verify
        raise VerificationError('Verification failed')
    rsa.pkcs1.VerificationError: Verification failed

.. note::

    Never display the stack trace of a
    :py:class:`rsa.pkcs1.VerificationError` exception. It shows where
    in the code the exception occurred, and thus leaks information
    about the key. It's only a tiny bit of information, but every bit
    makes cracking the keys easier.


Working with big files
--------------------------------------------------




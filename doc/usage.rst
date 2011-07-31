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

You can use the :py:func:`rsa.newkeys` function to create a keypair.
Alternatively you can use :py:func:`rsa.PrivateKey.load_pkcs1` and
:py:func:`rsa.PublicKey.load_pkcs1` to load keys from a file.

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

#. Alice writes a message

#. Alice encrypts the message using Bob's public key, and sends the
   encrypted message.

#. Bob receives the message, and decrypts it with his private key.

Since Bob kept his private key *private*, Alice can be sure that he is
the only one who can read the message. Bob does *not* know for sure
that it was Alice that sent the message, since she didn't sign it.


Low-level operations
++++++++++++++++++++++++++++++

The core RSA algorithm operates on large integers. These operations
are considered low-level and are supported by the
:py:func:`rsa.core.encrypt_int` and :py:func:`rsa.core.decrypt_int`
functions.

Signing and verification
--------------------------------------------------


Working with big files
--------------------------------------------------




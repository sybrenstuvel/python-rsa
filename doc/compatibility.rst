Compatibility with standards and other software
==================================================

.. index:: OpenSSL
.. index:: compatibility

Python-RSA implements encryption and signatures according to PKCS#1
version 1.5. This makes it compatible with the OpenSSL RSA module.

Keys are stored in PEM or DER format according to PKCS#1 v1.5. Private
keys are compatible with OpenSSL. However, OpenSSL uses X.509 for its
public keys, which are not supported.

:Encryption:
    PKCS#1 v1.5 with at least 8 bytes of random padding

:Signatures:
    PKCS#1 v1.5 using the following hash methods:
    MD5, SHA-1, SHA-256, SHA-384, SHA-512

:Private keys:
    PKCS#1 v1.5 in PEM and DER format, ASN.1 type RSAPrivateKey

:Public keys:
    PKCS#1 v1.5 in PEM and DER format, ASN.1 type RSAPublicKey

:VARBLOCK encryption:
    Python-RSA only, not compatible with any other known application.


Public keys from OpenSSL
--------------------------------------------------

To get a Python-RSA-compatible public key from OpenSSL, you need the
private key. Get the private key in PEM or DER format and run it
through the ``pyrsa-priv2pub`` command::

 
 Usage: pyrsa-priv2pub [options]
 
 Reads a private key and outputs the corresponding public key. Both
 private and public keys use the format described in PKCS#1 v1.5
 
 Options:
   -h, --help         show this help message and exit
   --in=INFILENAME    Input filename. Reads from stdin if not specified
   --out=OUTFILENAME  Output filename. Writes to stdout of not specified
   --inform=INFORM    key format of input - default PEM
   --outform=OUTFORM  key format of output - default PEM


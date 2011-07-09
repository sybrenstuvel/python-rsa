"""RSA module

Module for calculating large primes, and RSA encryption, decryption, signing
and verification. Includes generating public and private keys.

WARNING: this implementation does not use random padding, compression of the
cleartext input to prevent repetitions, or other common security improvements.
Use with care.

"""

__author__ = "Sybren Stuvel, Marloes de Boer, Ivo Tamboer, and Barry Mead"
__date__ = "2010-02-08"
__version__ = '2.1-beta0'

import functools

from rsa import transform
from rsa import common

from rsa.keygen import newkeys
from rsa.core import encrypt_int, decrypt_int

def get_blocks(message, block_size):
    '''Generator, yields the blocks of the message.'''
    
    msglen = len(message)
    blocks = msglen / block_size

    if msglen % block_size > 0:
        blocks += 1

    for bindex in range(blocks):
        offset = bindex * block_size
        yield message[offset:offset + block_size]

def encrypt(message, key, block_size):
    """Encrypts a string 'message' with the public key 'key'"""
    if 'n' not in key:
        raise Exception("You must use the public key with encrypt")

    op = functools.partial(encrypt_int, ekey=key['e'], n=key['n'])

    print 'E  : %i (%i bytes)' % (key['e'], transform.byte_size(key['e']))
    print 'N  : %i (%i bytes)' % (key['n'], transform.byte_size(key['n']))

    blocks = get_blocks(message, block_size)
    crypto = list(transform.block_op(blocks, block_size, op))

    return ''.join(crypto)

def sign(message, key):
    """Signs a string 'message' with the private key 'key'"""
    if 'p' not in key:
        raise Exception("You must use the private key with sign")

#    return chopstring(message, key['d'], key['p']*key['q'], encrypt_int)

def decrypt(cypher, key):
    """Decrypts a string 'cypher' with the private key 'key'"""
    if 'p' not in key:
        raise Exception("You must use the private key with decrypt")

#    return gluechops(cypher, key['d'], key['p']*key['q'], decrypt_int)

def verify(cypher, key):
    """Verifies a string 'cypher' with the public key 'key'"""
    if 'n' not in key:
        raise Exception("You must use the public key with verify")

#    return gluechops(cypher, key['e'], key['n'], decrypt_int)

# Do doctest if we're not imported
if __name__ == "__main__":
    import doctest
    doctest.testmod()

__all__ = ["newkeys", "encrypt", "decrypt", "sign", "verify"]


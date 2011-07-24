# -*- coding: utf-8 -*-
#
#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
"""RSA module

Module for calculating large primes, and RSA encryption, decryption, signing
and verification. Includes generating public and private keys.

WARNING: this implementation does not use random padding, compression of the
cleartext input to prevent repetitions, or other common security improvements.
Use with care.

If you want to have a more secure implementation, use the functions from the
``rsa.pkcs1`` module.

"""

__author__ = "Sybren Stuvel, Marloes de Boer, Ivo Tamboer, and Barry Mead"
__date__ = "2010-02-08"
__version__ = '2.1-beta0'

from rsa import common, key, transform
from rsa.core import encrypt_int, decrypt_int
from rsa.key import newkeys

def encode64chops(chops):
    """base64encodes chops and combines them into a ',' delimited string"""

    # chips are character chops
    chips = [transform.int2str64(chop) for chop in chops]

    # delimit chops with comma
    encoded = ','.join(chips)

    return encoded

def decode64chops(string):
    """base64decodes and makes a ',' delimited string into chops"""

    # split chops at commas
    chips = string.split(',')

    # make character chips into numeric chops
    chops = [transform.str642int(chip) for chip in chips]

    return chops

def block_size(n):
    '''Returns the block size in bytes, given the public key.

    The block size is determined by the 'n=p*q' component of the key.
    '''

    # Set aside 2 bits so setting of safebit won't overflow modulo n.
    nbits = common.bit_size(n) - 2
    nbytes = nbits // 8

    return nbytes


def chopstring(message, key, n, int_op):
    """Chops the 'message' into integers that fit into n.
    
    Leaves room for a safebit to be added to ensure that all messages fold
    during exponentiation. The MSB of the number n is not independent modulo n
    (setting it could cause overflow), so use the next lower bit for the
    safebit. Therefore this function reserves 2 bits in the number n for
    non-data bits.

    Calls specified encryption function 'int_op' for each chop before storing.

    Used by 'encrypt' and 'sign'.
    """


    nbytes = block_size(n)

    msglen = len(message)
    blocks = msglen // nbytes

    if msglen % nbytes > 0:
        blocks += 1

    cypher = []
    
    for bindex in range(blocks):
        offset = bindex * nbytes
        block = message[offset:offset + nbytes]

        value = transform.bytes2int(block)
        to_store = int_op(value, key, n)

        cypher.append(to_store)

    return encode64chops(cypher)   #Encode encrypted ints to base64 strings

def gluechops(string, key, n, funcref):
    """Glues chops back together into a string.  calls
    funcref(integer, key, n) for each chop.

    Used by 'decrypt' and 'verify'.
    """

    messageparts = []
    chops = decode64chops(string)  #Decode base64 strings into integer chops
    
    for chop in chops:
        value = funcref(chop, key, n) #Decrypt each chop
        block = transform.int2bytes(value)
        messageparts.append(block)

    # Combine decrypted strings into a msg
    return ''.join(messageparts)

def encrypt(message, pub_key):
    """Encrypts a string 'message' with the public key 'pub_key'"""

    if not isinstance(pub_key, key.PublicKey):
        raise TypeError("You must use the public key with encrypt")

    return chopstring(message, pub_key.e, pub_key.n, encrypt_int)

def sign(message, priv_key):
    """Signs a string 'message' with the private key 'priv_key'"""

    if not isinstance(priv_key, key.PrivateKey):
        raise TypeError("You must use the private key with sign")

    return chopstring(message, priv_key.d, priv_key.n, encrypt_int)

def decrypt(cypher, priv_key):
    """Decrypts a string 'cypher' with the private key 'priv_key'"""

    if not isinstance(priv_key, key.PrivateKey):
        raise TypeError("You must use the private key with decrypt")

    return gluechops(cypher, priv_key.d, priv_key.n, decrypt_int)

def verify(cypher, pub_key):
    """Verifies a string 'cypher' with the public key 'pub_key'"""

    if not isinstance(pub_key, key.PublicKey):
        raise TypeError("You must use the public pub_key with verify")

    return gluechops(cypher, pub_key.e, pub_key.n, decrypt_int)

# Do doctest if we're run directly
if __name__ == "__main__":
    import doctest
    doctest.testmod()

__all__ = ["newkeys", "encrypt", "decrypt", "sign", "verify"]


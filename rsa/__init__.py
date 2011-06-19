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

import rsa.prime
import rsa.transform
import rsa.common

from rsa.keygen import newkeys
from rsa.core import encrypt_int, decrypt_int

def encode64chops(chops):
    """base64encodes chops and combines them into a ',' delimited string"""

    # chips are character chops
    chips = [rsa.transform.int2str64(chop) for chop in chops]

    # delimit chops with comma
    encoded = ','.join(chips)

    return encoded

def decode64chops(string):
    """base64decodes and makes a ',' delimited string into chops"""

    # split chops at commas
    chips = string.split(',')

    # make character chips into numeric chops
    chops = [rsa.transform.str642int(chip) for chip in chips]

    return chops

def block_size(n):
    '''Returns the block size in bytes, given the public key.

    The block size is determined by the 'n=p*q' component of the key.
    '''

    # Set aside 2 bits so setting of safebit won't overflow modulo n.
    nbits = rsa.common.bit_size(n) - 2
    nbytes = nbits / 8

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
    blocks = msglen / nbytes

    if msglen % nbytes > 0:
        blocks += 1

    cypher = []
    
    for bindex in range(blocks):
        offset = bindex * nbytes
        block = message[offset:offset + nbytes]

        value = rsa.transform.bytes2int(block)
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

    nbytes = block_size(n)
    
    for chop in chops:
        value = funcref(chop, key, n) #Decrypt each chop
        block = rsa.transform.int2bytes(value)

        # Pad block with 0-bytes until we have reached the block size
        blocksize = len(block)
        padsize = nbytes - blocksize
        if padsize < 0:
            raise ValueError('Block larger than block size (%i > %i)!' %
                    (blocksize, nbytes))
        elif padsize > 0:
            block = '\x00' * padsize + block

        messageparts.append(block)

    # Combine decrypted strings into a msg
    return ''.join(messageparts)

def encrypt(message, key):
    """Encrypts a string 'message' with the public key 'key'"""
    if 'n' not in key:
        raise Exception("You must use the public key with encrypt")

    return chopstring(message, key['e'], key['n'], encrypt_int)

def sign(message, key):
    """Signs a string 'message' with the private key 'key'"""
    if 'p' not in key:
        raise Exception("You must use the private key with sign")

    return chopstring(message, key['d'], key['p']*key['q'], encrypt_int)

def decrypt(cypher, key):
    """Decrypts a string 'cypher' with the private key 'key'"""
    if 'p' not in key:
        raise Exception("You must use the private key with decrypt")

    return gluechops(cypher, key['d'], key['p']*key['q'], decrypt_int)

def verify(cypher, key):
    """Verifies a string 'cypher' with the public key 'key'"""
    if 'n' not in key:
        raise Exception("You must use the public key with verify")

    return gluechops(cypher, key['e'], key['n'], decrypt_int)

# Do doctest if we're not imported
if __name__ == "__main__":
    import doctest
    doctest.testmod()

__all__ = ["newkeys", "encrypt", "decrypt", "sign", "verify"]


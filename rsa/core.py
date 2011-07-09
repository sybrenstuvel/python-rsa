'''Core mathematical operations.

This is the actual core RSA implementation, which is only defined
mathematically on integers.
'''

import types

import rsa.common

def encrypt_int(message, ekey, n):
    """Encrypts a message using encryption key 'ekey', working modulo n"""

    if type(message) is types.IntType:
        message = long(message)

    if not type(message) is types.LongType:
        raise TypeError("You must pass a long or int")

    if message < 0 or message > n:
        raise OverflowError("The message is too long")

    #Note: Bit exponents start at zero (bit counts start at 1) this is correct
    safebit = rsa.common.bit_size(n) - 2        # compute safe bit (MSB - 1)
    message += (1 << safebit)                   # add safebit to ensure folding

    return pow(message, ekey, n)

def decrypt_int(cyphertext, dkey, n):
    """Decrypts a cypher text using the decryption key 'dkey', working
    modulo n"""

    message = pow(cyphertext, dkey, n)

    safebit = rsa.common.bit_size(n) - 2        # compute safe bit (MSB - 1)
    message -= (1 << safebit)                   # remove safebit before decode

    return message


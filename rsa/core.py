'''Core mathematical operations.

This is the actual core RSA implementation, which is only defined
mathematically on integers.
'''

import types

def encrypt_int(message, ekey, n):
    """Encrypts a message using encryption key 'ekey', working modulo n"""

    if type(message) is types.IntType:
        message = long(message)

    if not type(message) is types.LongType:
        raise TypeError("You must pass a long or int")

    if message < 0:
        raise ValueError('Only non-negative numbers are supported')
         
    if message > n:
        raise OverflowError("The message %i is too long for n=%i" % (message, n))

    return pow(message, ekey, n)

def decrypt_int(cyphertext, dkey, n):
    """Decrypts a cypher text using the decryption key 'dkey', working
    modulo n"""

    message = pow(cyphertext, dkey, n)
    return message


"""RSA module

Module for calculating large primes, and RSA encryption, decryption,
signing and verification. Includes generating public and private keys.

WARNING: this implementation does not use random padding, compression of the
cleartext input to prevent repetitions, or other common security improvements.
Use with care.

"""

__author__ = "Sybren Stuvel, Marloes de Boer, Ivo Tamboer, and Barry Mead"
__date__ = "2010-02-08"
__version__ = '2.1-beta0'

import math
import types

import rsa.prime
import rsa.transform

def bit_size(number):
    """Returns the number of bits required to hold a specific long number"""

    return int(math.ceil(math.log(number,2)))


def extended_gcd(a, b):
    """Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    """
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a                             #Remember original a/b to remove 
    ob = b                             #negative values from return results
    while b != 0:
        q = long(a/b)
        (a, b)  = (b, a % b)
        (x, lx) = ((lx - (q * x)),x)
        (y, ly) = ((ly - (q * y)),y)
    if (lx < 0): lx += ob              #If neg wrap modulo orignal b
    if (ly < 0): ly += oa              #If neg wrap modulo orignal a
    return (a, lx, ly)                 #Return only positive values

def find_p_q(nbits):
    """Returns a tuple of two different primes of nbits bits"""
    pbits = nbits + (nbits/16)  #Make sure that p and q aren't too close
    qbits = nbits - (nbits/16)  #or the factoring programs can factor n
    p = rsa.prime.getprime(pbits)
    while True:
        q = rsa.prime.getprime(qbits)

        #Make sure p and q are different.
        if q != p: break

    return (p, q)



# Main function: calculate encryption and decryption keys
def calculate_keys(p, q, nbits):
    """Calculates an encryption and a decryption key for p and q, and
    returns them as a tuple (e, d)"""

    n = p * q
    phi_n = (p-1) * (q-1)

    while True:
        # Make sure e has enough bits so we ensure "wrapping" through
        # modulo n
        e = max(65537, rsa.prime.getprime(nbits/4))
        if rsa.prime.are_relatively_prime(e, n) and rsa.prime.are_relatively_prime(e, phi_n):
            break

    (d, i, j) = extended_gcd(e, phi_n)

    if not d == 1:
        raise Exception("e (%d) and phi_n (%d) are not relatively prime" % (e, phi_n))
    if (i < 0):
        raise Exception("New extended_gcd shouldn't return negative values")
    if not (e * i) % phi_n == 1:
        raise Exception("e (%d) and i (%d) are not mult. inv. modulo phi_n (%d)" % (e, i, phi_n))

    return (e, i)


def gen_keys(nbits):
    """Generate RSA keys of nbits bits. Returns (p, q, e, d).

    Note: this can take a long time, depending on the key size.
    """

    (p, q) = find_p_q(nbits)
    (e, d) = calculate_keys(p, q, nbits)

    return (p, q, e, d)

def newkeys(nbits):
    """Generates public and private keys, and returns them as (pub,
    priv).

    The public key consists of a dict {e: ..., , n: ....). The private
    key consists of a dict {d: ...., p: ...., q: ....).
    """
    nbits = max(9,nbits)           # Don't let nbits go below 9 bits
    (p, q, e, d) = gen_keys(nbits)

    return ( {'e': e, 'n': p*q}, {'d': d, 'p': p, 'q': q} )

def encrypt_int(message, ekey, n):
    """Encrypts a message using encryption key 'ekey', working modulo n"""

    if type(message) is types.IntType:
        message = long(message)

    if not type(message) is types.LongType:
        raise TypeError("You must pass a long or int")

    if message < 0 or message > n:
        raise OverflowError("The message is too long")

    #Note: Bit exponents start at zero (bit counts start at 1) this is correct
    safebit = bit_size(n) - 2                   #compute safe bit (MSB - 1)
    message += (1 << safebit)                   #add safebit to ensure folding

    return pow(message, ekey, n)

def decrypt_int(cyphertext, dkey, n):
    """Decrypts a cypher text using the decryption key 'dkey', working
    modulo n"""

    message = pow(cyphertext, dkey, n)

    safebit = bit_size(n) - 2                   #compute safe bit (MSB - 1)
    message -= (1 << safebit)                   #remove safebit before decode

    return message

def encode64chops(chops):
    """base64encodes chops and combines them into a ',' delimited string"""

    chips = []                              #chips are character chops

    for value in chops:
        as_str = rsa.transform.int2str64(value)
        chips.append(as_str)

    #delimit chops with comma
    encoded = ','.join(chips)

    return encoded

def decode64chops(string):
    """base64decodes and makes a ',' delimited string into chops"""

    chips = string.split(',')               #split chops at commas

    chops = []

    for string in chips:                    #make char chops (chips) into chops
        as_int = rsa.transform.str642int(string)
        chops.append(as_int)

    return chops

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

    msglen = len(message)
    mbits = msglen * 8

    # Set aside 2 bits so setting of safebit won't overflow modulo n.
    nbits = bit_size(n) - 2             # leave room for safebit
    nbytes = nbits / 8
    blocks = msglen / nbytes

    if msglen % nbytes > 0:
        blocks += 1

    cypher = []
    
    for bindex in range(blocks):
        offset = bindex * nbytes
        block = message[offset:offset+nbytes]
        value = rsa.transform.bytes2int(block)
        cypher.append(int_op(value, key, n))

    return encode64chops(cypher)   #Encode encrypted ints to base64 strings

def gluechops(string, key, n, funcref):
    """Glues chops back together into a string.  calls
    funcref(integer, key, n) for each chop.

    Used by 'decrypt' and 'verify'.
    """
    message = ""

    chops = decode64chops(string)  #Decode base64 strings into integer chops
    
    for cpart in chops:
        mpart = funcref(cpart, key, n) #Decrypt each chop
        message += rsa.transform.int2bytes(mpart)    #Combine decrypted strings into a msg
    
    return message

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


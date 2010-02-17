"""RSA module

Module for calculating large primes, and RSA encryption, decryption,
signing and verification. Includes generating public and private keys.
"""

__author__ = "Sybren Stuvel, Marloes de Boer, Ivo Tamboer, and Barry Mead"
__date__ = "2010-02-08"

import math
import os
import random
import sys
import types

def gcd(p, q):
    """Returns the greatest common divisor of p and q
    >>> gcd(48, 180)
    12
    """
    # Iterateive Version is faster and uses much less stack space
    while q != 0:
        if p < q: (p,q) = (q,p)
        (p,q) = (q, p % q)
    return p
    

def bytes2int(bytes):
    """Converts a list of bytes or a string to an integer

    >>> (((128 * 256) + 64) * 256) + 15
    8405007
    >>> l = [128, 64, 15]
    >>> bytes2int(l)              #same as bytes2int('\x80@\x0f')
    8405007
    """

    if not (type(bytes) is types.ListType or type(bytes) is types.StringType):
        raise TypeError("You must pass a string or a list")

    # Convert byte stream to integer
    integer = 0
    for byte in bytes:
        integer *= 256
        if type(byte) is types.StringType: byte = ord(byte)
        integer += byte

    return integer

def int2bytes(number):
    """Converts a number to a string of bytes
    
    >>>int2bytes(123456789)
    '\x07[\xcd\x15'
    >>> bytes2int(int2bytes(123456789))
    123456789
    """

    if not (type(number) is types.LongType or type(number) is types.IntType):
        raise TypeError("You must pass a long or an int")

    string = ""

    while number > 0:
        string = "%s%s" % (chr(number & 0xFF), string)
        number /= 256
    
    return string

def to64(number):
    """Converts a number in the range of 0 to 63 into base 64 digit
    character in the range of '0'-'9', 'A'-'Z', 'a'-'z','-','_'.
    
    >>> to64(10)
    'A'
    """

    if not (type(number) is types.LongType or type(number) is types.IntType):
        raise TypeError("You must pass a long or an int")

    if 0 <= number <= 9:            #00-09 translates to '0' - '9'
        return chr(number + 48)

    if 10 <= number <= 35:
        return chr(number + 55)     #10-35 translates to 'A' - 'Z'

    if 36 <= number <= 61:
        return chr(number + 61)     #36-61 translates to 'a' - 'z'

    if number == 62:                # 62   translates to '-' (minus)
        return chr(45)

    if number == 63:                # 63   translates to '_' (underscore)
        return chr(95)


def from64(number):
    """Converts an ordinal character value in the range of
    0-9,A-Z,a-z,-,_ to a number in the range of 0-63.
    
    >>> from64(49)
    1
    """

    if not (type(number) is types.LongType or type(number) is types.IntType):
        raise TypeError("You must pass a long or an int")

    if 48 <= number <= 57:         #ord('0') - ord('9') translates to 0-9
        return(number - 48)

    if 65 <= number <= 90:         #ord('A') - ord('Z') translates to 10-35
        return(number - 55)

    if 97 <= number <= 122:        #ord('a') - ord('z') translates to 36-61
        return(number - 61)

    if number == 45:               #ord('-') translates to 62
        return(62)

    if number == 95:               #ord('_') translates to 63
        return(63)



def int2str64(number):
    """Converts a number to a string of base64 encoded characters in
    the range of '0'-'9','A'-'Z,'a'-'z','-','_'.
    
    >>> int2str64(123456789)
    '7MyqL'
    """

    if not (type(number) is types.LongType or type(number) is types.IntType):
        raise TypeError("You must pass a long or an int")

    string = ""

    while number > 0:
        string = "%s%s" % (to64(number & 0x3F), string)
        number /= 64

    return string


def str642int(string):
    """Converts a base64 encoded string into an integer.
    The chars of this string in in the range '0'-'9','A'-'Z','a'-'z','-','_'
    
    >>> str642int('7MyqL')
    123456789
    """

    if not (type(string) is types.ListType or type(string) is types.StringType):
        raise TypeError("You must pass a string or a list")

    integer = 0
    for byte in string:
        integer *= 64
        if type(byte) is types.StringType: byte = ord(byte)
        integer += from64(byte)

    return integer


def fast_exponentiation(a, e, n):
    """Calculates r = a^e mod n
    """
    #Single loop version is faster and uses less memory
    #MSB is always 1 so skip testing it and start with result = a
    msbe = int(math.ceil(math.log(e,2))) - 2  #Find MSB-1 of exponent
    test = long(1 << msbe)
    a %= n                      #Throw away any overflow
    result = a                  #Start with result = a (skip MSB test)
    while test != 0:
        if e & test != 0:       #If exponent bit 1 square and mult by a
            result = (result * result * a) % n
        else:                   #If exponent bit 0 just square
            result = (result * result) % n   
        test >>= 1              #Move to next exponent bit
    return result

def read_random_int(nbits):
    """Reads a random integer of approximately nbits bits rounded up
    to whole bytes"""

    nbytes = int(math.ceil(nbits/8.))
    randomdata = os.urandom(nbytes)
    return bytes2int(randomdata)

def randint(minvalue, maxvalue):
    """Returns a random integer x with minvalue <= x <= maxvalue"""

    # Safety - get a lot of random data even if the range is fairly
    # small
    min_nbits = 32

    # The range of the random numbers we need to generate
    range = maxvalue - minvalue

    # Which is this number of bytes
    rangebytes = int(math.ceil(math.log(range, 2) / 8.))

    # Convert to bits, but make sure it's always at least min_nbits*2
    rangebits = max(rangebytes * 8, min_nbits * 2)
    
    # Take a random number of bits between min_nbits and rangebits
    nbits = random.randint(min_nbits, rangebits)
    
    return (read_random_int(nbits) % range) + minvalue

def jacobi(a, b):
    """Calculates the value of the Jacobi symbol (a/b)
    where both a and b are positive integers, and b is odd
    """

    if a == 0: return 0
    result = 1
    while a > 1:
        if a & 1:
            if ((a-1)*(b-1) >> 2) & 1:
                result = -result
            a, b = b % a, a
        else:
            if (((b ** 2) - 1) >> 3) & 1:
                result = -result
            a >>= 1
    if a == 0: return 0
    return result

def jacobi_witness(x, n):
    """Returns False if n is an Euler pseudo-prime with base x, and
    True otherwise.
    """

    j = jacobi(x, n) % n
    f = fast_exponentiation(x, (n-1)/2, n)

    if j == f: return False
    return True

def randomized_primality_testing(n, k):
    """Calculates whether n is composite (which is always correct) or
    prime (which is incorrect with error probability 2**-k)

    Returns False if the number if composite, and True if it's
    probably prime.
    """

    # 50% of Jacobi-witnesses can report compositness of non-prime numbers

    for i in range(k):
        x = randint(1, n-1)
        if jacobi_witness(x, n): return False
    
    return True

def is_prime(number):
    """Returns True if the number is prime, and False otherwise.

    >>> is_prime(42)
    0
    >>> is_prime(41)
    1
    """

    if randomized_primality_testing(number, 6):
        # Prime, according to Jacobi
        return True
    
    # Not prime
    return False

    
def getprime(nbits):
    """Returns a prime number of max. 'math.ceil(nbits/8)*8' bits. In
    other words: nbits is rounded up to whole bytes.

    >>> p = getprime(8)
    >>> is_prime(p-1)
    0
    >>> is_prime(p)
    1
    >>> is_prime(p+1)
    0
    """

    while True:
        integer = read_random_int(nbits)

        # Make sure it's odd
        integer |= 1

        # Test for primeness
        if is_prime(integer): break

        # Retry if not prime

    return integer

def are_relatively_prime(a, b):
    """Returns True if a and b are relatively prime, and False if they
    are not.

    >>> are_relatively_prime(2, 3)
    1
    >>> are_relatively_prime(2, 4)
    0
    """

    d = gcd(a, b)
    return (d == 1)

def find_p_q(nbits):
    """Returns a tuple of two different primes of nbits bits"""
    pbits = nbits + (nbits/16)  #Make sure that p and q aren't too close
    qbits = nbits - (nbits/16)  #or the factoring programs can factor n
    while True:
        p = getprime(pbits)
        q = getprime(qbits)
        phi_n = (p-1)*(q-1)
        #Make sure p and q are different and phi_n is not divisible by 256
        if not (q == p or phi_n & 255 == 0): break
    return (p, q)

def extended_gcd(a, b):
    """Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    """
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a                             #Remember original a/b to remove
    ob = b                             #negative values modulo b or a
    while b != 0:
        q = long(a/b)
        (a, b)  = (b, a % b)
        (x, lx) = ((lx - (q * x)),x)
        (y, ly) = ((ly - (q * y)),y)
    if (lx < 0): lx += ob              #If negative wrap modulo original b
    if (ly < 0): ly += oa              #If negative wrap modulo original a
    return (a, lx, ly)

# Main function: calculate encryption and decryption keys
def calculate_keys(p, q, nbits):
    """Calculates an encryption and a decryption key for p and q, and
    returns them as a tuple (e, dp, dq, qi)"""

    n = p * q
    phi_n = (p-1) * (q-1)

    while True:
        # Make sure e has enough bits so we ensure "wrapping" through
        # modulo n
        e = max(65537,getprime(nbits/4)) #minimum e is 65537 per RSA spec
        if are_relatively_prime(e, n) and are_relatively_prime(e, phi_n): break

    (r, dp, j) = extended_gcd(e, p-1) #Compute exponent dp

    if not r == 1:
        raise Exception("e (%d) and p-1 (%d) are not relatively prime" % (e, p-1))

    (r, dq, j) = extended_gcd(e, q-1) #Compute exponent dq

    if not r == 1:
        raise Exception("e (%d) and q-1 (%d) are not relatively prime" % (e, q-1))

    (r, qi, j) = extended_gcd(q, p)   #Compute coefficent qi

    if not r == 1:
        raise Exception("q (%d) and p (%d) are not relatively prime" % (q, p))

    return (e, dp, dq, qi)


def gen_keys(nbits):
    """Generate RSA keys of nbits bits. Returns (p, q, e, d).

    Note: this can take a long time, depending on the key size.
    """

    (p, q) = find_p_q(nbits)
    (e, dp, dq, qi) = calculate_keys(p, q, nbits)

    return (p, q, e, dp, dq, qi)

def newkeys(nbits):
    """Generates public and private keys, and returns them as (pub,
    priv).

    The public key consists of a dict {e: ..., n: ...}. The private
    key consists of a dict {p: ..., q: ..., dp: ..., dq: ..., qi: ...}.
    """
    nbits = max(9,nbits)         #Minimum key size is 9 bits for p and q 
    (p, q, e, dp, dq, qi) = gen_keys(nbits)

    return ( {'e':e,'n':p*q}, {'p':p,'q':q,'dp':dp,'dq':dq,'qi':qi} )

def encrypt_int(message, key):
    """Encrypts a message using public key 'key', working modulo n"""

    if type(message) is types.IntType:
        message = long(message)

    if not type(message) is types.LongType:
        raise TypeError("You must pass a long or int")

    if message < 0 or message > key['n']:
        raise OverflowError("The message is too long")

    #Note: Bit exponents start at zero (bit counts start at 1) this is correct
    safebit = int(math.floor(math.log(key['n'],2))) - 1 #safe bit is (MSB - 1)
    message += (1 << safebit)                    #add safebit to ensure folding

    return fast_exponentiation(message, key['e'], key['n'])

def verify_int(cyphertext, key):
    """Decrypts cyphertext using public key 'key', working modulo n"""

    if type(cyphertext) is types.IntType:
        cyphertext = long(cyphertext)

    if not type(cyphertext) is types.LongType:
        raise TypeError("You must pass a long or int")

    message = fast_exponentiation(cyphertext, key['e'], key['n'])

    #Note: Bit exponents start at zero (bit counts start at 1) this is correct
    safebit = int(math.floor(math.log(key['n'],2))) - 1 #safe bit is (MSB - 1)
    message -= (1 << safebit)                  #remove safe bit before decode

    return message

def decrypt_int(cyphertext, key):
    """Decrypts a cypher text using the private key 'key', working
    modulo n"""

    n = key['p'] * key['q']
    #Decrypt in 2 parts, using faster Chinese Remainder Theorem method
    m1 = fast_exponentiation(cyphertext, key['dp'], key['p'])
    m2 = fast_exponentiation(cyphertext, key['dq'], key['q'])
    dif = m1 - m2
    if dif < 0: dif += key['p']
    h = (key['qi'] * dif) % key['p']
    message = m2 + (h * key['q'])

    safebit = int(math.floor(math.log(n,2))) - 1 #safe bit is (MSB - 1)
    message -= (1 << safebit)                    #remove safebit before decode

    return message

def sign_int(message, key):
    """Encrypts a message with the private key 'key', working
    modulo n"""

    if type(message) is types.IntType:
        message = long(message)

    if not type(message) is types.LongType:
        raise TypeError("You must pass a long or int")

    n = key['p'] * key['q']                      #computer n from p and q

    if message < 0 or message > n:
        raise OverflowError("The message is too long")

    safebit = int(math.floor(math.log(n,2))) - 1 #safe bit is (MSB - 1)
    message += (1 << safebit)                    #add safebit before encrypt

    #Encrypt in 2 parts, using faster Chinese Remainder Theorem method
    c1 = fast_exponentiation(message, key['dp'], key['p'])
    c2 = fast_exponentiation(message, key['dq'], key['q'])
    dif = c1 - c2
    if dif < 0: dif += key['p']
    h = (key['qi'] * dif) % key['p']
    cyphertext = c2 + (h * key['q'])

    return cyphertext

def encode64chops(chops):
    """base64encodes chops and combines them into a ',' delimited string"""

    chips = []                              #chips are character chops

    for value in chops:
        chips.append(int2str64(value))

    encoded = ""

    for string in chips:
        encoded = encoded + string + ','    #delimit chops with comma

    return encoded

def decode64chops(string):
    """base64decodes and makes a ',' delimited string into chops"""

    chips = string.split(',')               #split chops at commas

    chops = []

    for string in chips:                    #make char chops (chips) into chops
        chops.append(str642int(string))

    return chops

def chopstring(message, key, funcref):
    """Chops the 'message' into integers that fit into n,
    leaving room for a safebit to be added to ensure that all
    messages fold during exponentiation.  The MSB of the number n
    is not independant modulo n (setting it could cause overflow), so
    use the next lower bit for the safebit.  Therefore reserve 2-bits
    in the number n for non-data bits.  Calls specified encryption
    function for each chop.

    Used by 'encrypt' and 'sign'.
    """

    if key.__contains__('n'):
        n = key['n']                        #Public key has n already
    else:
        n = key['p'] * key['q']             #Private key has p & q
    
    msglen = len(message)
    mbits = msglen * 8
    # floor of log deducts 1 bit of n and the - 1, deducts the second bit.
    nbits = int(math.floor(math.log(n, 2))) - 1 # leave room for safebit
    nbytes = nbits / 8
    blocks = msglen / nbytes

    if msglen % nbytes > 0:
        blocks += 1

    cypher = []
    
    for bindex in range(blocks):
        offset = bindex * nbytes
        block = message[offset:offset+nbytes]
        value = bytes2int(block)
        cypher.append(funcref(value, key))

    return encode64chops(cypher)   #Encode encrypted ints to base64 strings

def gluechops(string, key, funcref):
    """Glues chops back together into a string.  calls
    funcref(integer, key) for each chop.

    Used by 'decrypt' and 'verify'.
    """
    message = ""

    chops = decode64chops(string)  #Decode base64 strings into integer chops
    
    for cpart in chops:
        mpart = funcref(cpart, key)    #Decrypt each chop
        message += int2bytes(mpart)    #Combine decrypted strings into a msg
    
    return message

def encrypt(message, key):
    """Encrypts a string 'message' with the public key 'key'"""
    if key.__contains__('n'):
        return chopstring(message, key, encrypt_int)
    else:
        raise Exception("You must use the public key with encrypt")

def sign(message, key):
    """Signs a string 'message' with the private key 'key'"""
    if key.__contains__('p'):
        return chopstring(message, key, sign_int)
    else:
        raise Exception("You must use the private key with sign")

def decrypt(cypher, key):
    """Decrypts a cypher with the private key 'key'"""
    if key.__contains__('p'):
        return gluechops(cypher, key, decrypt_int)
    else:
        raise Exception("You must use the private key with decrypt")

def verify(cypher, key):
    """Verifies a cypher with the public key 'key'"""
    if key.__contains__('n'):
        return gluechops(cypher, key, verify_int)
    else:
        raise Exception("You must use the public key with verify")

# Do doctest if we're not imported
if __name__ == "__main__":
    import doctest
    doctest.testmod()

__all__ = ["newkeys", "encrypt", "decrypt", "sign", "verify"]


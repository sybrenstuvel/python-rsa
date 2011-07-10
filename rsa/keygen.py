'''RSA key generation code.

Create new keys with the newkeys() function.

The private key consists of a dict {d: ...., p: ...., q: ....).

The public key consists of a dict {e: ..., , n: p*q)


'''

import rsa.prime

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
    ''''Returns a tuple of two different primes of nbits bits each.
    
    >>> (p, q) = find_p_q(128)
    
    The resulting p and q should be very close to 2*nbits bits, and no more
    than 2*nbits bits:
    >>> from rsa import common
    >>> common.bit_size(p * q) <= 256
    True
    >>> common.bit_size(p * q) > 240
    True
    
    '''
    
    # Make sure that p and q aren't too close or the factoring programs can
    # factor n.
    shift = nbits / 16
    pbits = nbits + shift
    qbits = nbits - shift
    
    p = rsa.prime.getprime(pbits)
    
    while True:
        q = rsa.prime.getprime(qbits)

        #Make sure p and q are different.
        if q != p: break

    return (p, q)

def calculate_keys(p, q, nbits):
    """Calculates an encryption and a decryption key given p and q, and
    returns them as a tuple (e, d)

    """

    n = p * q
    phi_n = (p-1) * (q-1)

    while True:
        # Make sure e has enough bits so we ensure "wrapping" through
        # modulo n
        e = max(65537, rsa.prime.getprime(nbits/4))
        if rsa.prime.are_relatively_prime(e, n) and rsa.prime.are_relatively_prime(e, phi_n):
            break

    (d, i, _) = extended_gcd(e, phi_n)

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
    
    @param nbits: the total number of bits in ``p`` and ``q``. Both ``p`` and
        ``q`` will use ``nbits/2`` bits.
    """

    (p, q) = find_p_q(nbits / 2)
    (e, d) = calculate_keys(p, q, nbits / 2)

    return (p, q, e, d)

def newkeys(nbits):
    """Generates public and private keys, and returns them as (pub,
    priv).

    The public key consists of a dict {e: ..., , n: ....). The private
    key consists of a dict {d: ...., p: ...., q: ...., n: p*q).
    
    @param nbits: the number of bits required to store ``n = p*q``.
    
    """

    # Don't let nbits go below 9 bits
    nbits = max(9, nbits)
    (p, q, e, d) = gen_keys(nbits)
    
    n = p * q

    return ( {'e': e, 'n': n}, {'d': d, 'p': p, 'q': q, 'n': n} )

    
if __name__ == '__main__':
    print 'Running doctests 1000x or until failure'
    import doctest
    
    for count in range(1000):
        (failures, tests) = doctest.testmod()
        if failures:
            break
        
        if count and count % 100 == 0:
            print '%i times' % count
    
    print 'Doctests done'

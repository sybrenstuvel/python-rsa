'''Functions for generating random numbers.'''

import os

from rsa import common, transform

def read_random_int(nbits):
    """Reads a random integer of approximately nbits bits.
    
    The number of bits is rounded down to whole bytes to ensure that the
    resulting number can be stored in ``nbits`` bits.
    """

    randomdata = os.urandom(nbits // 8)
    return transform.bytes2int(randomdata)

def randint(maxvalue):
    """Returns a random integer x with 1 <= x <= maxvalue"""


    # Safety - get a lot of random data even if the range is fairly
    # small
    readbits = max(common.bit_size(maxvalue), 32)

    return (read_random_int(readbits) % maxvalue) + 1


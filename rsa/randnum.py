'''Functions for generating random numbers.'''

import math
import os
import random

import rsa.transform

def read_random_int(nbits):
    """Reads a random integer of approximately nbits bits rounded up to whole
    bytes
    """

    nbytes = int(math.ceil(nbits/8.))
    randomdata = os.urandom(nbytes)
    return rsa.transform.bytes2int(randomdata)

def randint(minvalue, maxvalue):
    """Returns a random integer x with minvalue <= x <= maxvalue"""

    # Safety - get a lot of random data even if the range is fairly
    # small
    min_nbits = 32

    # The range of the random numbers we need to generate
    range = (maxvalue - minvalue) + 1

    # Which is this number of bytes
    rangebytes = (rsa.transform.bit_size(range) + 7) / 8

    # Convert to bits, but make sure it's always at least min_nbits*2
    rangebits = max(rangebytes * 8, min_nbits * 2)
    
    # Take a random number of bits between min_nbits and rangebits
    nbits = random.randint(min_nbits, rangebits)
    
    return (read_random_int(nbits) % range) + minvalue


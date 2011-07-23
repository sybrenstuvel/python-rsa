'''Functions for generating random numbers.'''

import math
import os
import random

from rsa import common, transform

def read_random_int(nbits):
    """Reads a random integer of approximately nbits bits.
    
    The number of bits is rounded down to whole bytes to ensure that the
    resulting number can be stored in ``nbits`` bits.
    """

    randomdata = os.urandom(int(math.ceil(nbits / 8.0)))
    return transform.bytes2int(randomdata)

def randint(maxvalue):
    """Returns a random integer x with 1 <= x <= maxvalue"""

    readbits = max(common.bit_size(maxvalue), 32)

    while True:
        value = read_random_int(readbits)
        if value <= maxvalue:
            return value


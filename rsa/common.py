'''Common functionality shared by several modules.'''

import math

def bit_size(number):
    '''Returns the number of bits required to hold a specific long number.

    >>> bit_size(1023)
    10
    >>> bit_size(1024)
    10
    >>> bit_size(1025)
    11

    '''

    return int(math.ceil(math.log(number, 2)))


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

    if number < 0:
        raise ValueError('Only nonnegative numbers possible: %s' % number)

    if number == 0:
        return 1
    
    return int(math.ceil(math.log(number, 2)))

def byte_size(number):
    """Returns the number of bytes required to hold a specific long number.
    
    The number of bytes is rounded up.
    """

    return int(math.ceil(bit_size(number) / 8.0))

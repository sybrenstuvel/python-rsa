'''Common functionality shared by several modules.'''

import math

def bit_size(number):
    '''Returns the number of bits required to hold a specific long number.

    >>> bit_size(1023)
    10
    >>> bit_size(1024)
    11
    >>> bit_size(1025)
    11

    >>> bit_size(1 << 1024)
    1025
    >>> bit_size((1 << 1024) + 1)
    1025
    >>> bit_size((1 << 1024) - 1)
    1024

    '''

    if number < 0:
        raise ValueError('Only nonnegative numbers possible: %s' % number)

    if number == 0:
        return 1
    
    # This works, even with very large numbers. When using math.log(number, 2),
    # you'll get rounding errors and it'll fail.
    bits = 0
    while number:
        bits += 1
        number >>= 1

    return bits


def byte_size(number):
    """Returns the number of bytes required to hold a specific long number.
    
    The number of bytes is rounded up.

    >>> byte_size(1 << 1023)
    128
    >>> byte_size((1 << 1024) - 1)
    128
    >>> byte_size(1 << 1024)
    129
    """

    return int(math.ceil(bit_size(number) / 8.0))

if __name__ == '__main__':
    import doctest
    doctest.testmod()


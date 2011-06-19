'''Common functionality shared by several modules.'''

import math

def bit_size(number):
    """Returns the number of bits required to hold a specific long number"""

    return int(math.ceil(math.log(number,2)))


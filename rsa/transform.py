# -*- coding: utf-8 -*-
#
#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

'''Data transformation functions.

From bytes to a number, number to bytes, etc.
'''

from __future__ import absolute_import

import binascii
from struct import pack
from rsa._compat import is_integer, b

ZERO_BYTE = b('\x00')


def bytes2int(raw_bytes):
    r"""Converts a list of bytes or an 8-bit string to an integer.

    When using unicode strings, encode it to some encoding like UTF8 first.

    >>> (((128 * 256) + 64) * 256) + 15
    8405007
    >>> bytes2int('\x80@\x0f')
    8405007

    """

    return int(binascii.hexlify(raw_bytes), 16)


def int2bytes(number, block_size=None):
    r'''Converts a number to a string of bytes.

    @param number: the number to convert
    @param block_size: the number of bytes to output. If the number encoded to
        bytes is less than this, the block will be zero-padded. When not given,
        the returned block is not padded.

    @throws OverflowError when block_size is given and the number takes up more
        bytes than fit into the block.


    >>> int2bytes(123456789)
    '\x07[\xcd\x15'
    >>> bytes2int(int2bytes(123456789))
    123456789

    >>> int2bytes(123456789, 6)
    '\x00\x00\x07[\xcd\x15'
    >>> bytes2int(int2bytes(123456789, 128))
    123456789

    >>> int2bytes(123456789, 3)
    Traceback (most recent call last):
    ...
    OverflowError: Needed 4 bytes for number, but block size is 3

    '''

    # Type checking
    if not is_integer(number):
        raise TypeError("You must pass an integer for 'number', not %s" %
            type(number).__name__)

    if number < 0:
        raise ValueError('Negative numbers cannot be used: %i' % number)

    # Convert the number to bytes.
    raw_bytes = b('')
    while number > 0:
        raw_bytes = pack(">I", number & 0xffffffff) + raw_bytes
        number >>= 32

    # Pad with zeroes to fill the block
    if block_size is not None and block_size > 0:
        # Best-case is where you wouldn't specify a block size that
        # causes an overflow. So doing a bounds check here is better than
        # doing it up-front.
        length = len(raw_bytes)
        zero_leading = 0
        for zero_leading, x in enumerate(raw_bytes):
            if x != ZERO_BYTE[0]:
                break
        needed_bytes = length - zero_leading
        if needed_bytes > block_size:
            raise OverflowError('Needed %i bytes for number, but block size '
                'is %i' % (needed_bytes, block_size))

        remainder = length % block_size
        if remainder:
            raw_bytes = ((block_size - remainder) * ZERO_BYTE) + raw_bytes
    return raw_bytes


if __name__ == '__main__':
    import doctest
    doctest.testmod()


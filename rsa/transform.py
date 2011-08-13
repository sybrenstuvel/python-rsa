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

try:
    # We'll use psyco if available on 32-bit architectures to speed up code.
    # Using psyco (if available) cuts down the execution time on Python 2.5
    # at least by half.
    import psyco
    psyco.full()
except ImportError:
    pass

import binascii
from struct import pack
from rsa import common
from rsa._compat import is_integer, b, byte, get_machine_alignment


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


def _int2bytes(number, block_size=0):
    """Converts a number to a string of bytes.

    @param number: the number to convert
    @param block_size: the number of bytes to output. If the number encoded to
        bytes is less than this, the block will be zero-padded. When not given,
        the returned block is not padded.

    @throws OverflowError when block_size is given and the number takes up more
        bytes than fit into the block.

    >>> _int2bytes(123456789)
    b'\x07[\xcd\x15'
    >>> bytes2int(int2bytes(123456789))
    123456789

    >>> _int2bytes(123456789, 6)
    b'\x00\x00\x07[\xcd\x15'
    >>> bytes2int(int2bytes(123456789, 128))
    123456789

    >>> _int2bytes(123456789, 3)
    Traceback (most recent call last):
    ...
    OverflowError: Needed 4 bytes for number, but block size is 3

    """
    # Type checking
    if not is_integer(number):
        raise TypeError("You must pass an integer for 'number', not %s" %
            number.__class__)

    if number < 0:
        raise ValueError('Negative numbers cannot be used: %i' % number)

    # Do some bounds checking
    needed_bytes = common.byte_size(number)
    if block_size > 0:
        if needed_bytes > block_size:
            raise OverflowError('Needed %i bytes for number, but block size '
                'is %i' % (needed_bytes, block_size))

    # Convert the number to bytes.
    raw_bytes = []
    while number > 0:
        raw_bytes.insert(0, byte(number & 0xFF))
        number >>= 8

    # Pad with zeroes to fill the block
    if block_size > 0:
        padding = (block_size - needed_bytes) * ZERO_BYTE
    else:
        padding = b('')

    return padding + b('').join(raw_bytes)



def int2bytes(number, chunk_size=0,
                     _zero_byte=ZERO_BYTE,
                     _get_machine_alignment=get_machine_alignment):
    """
    Convert a integer to bytes (base-256 representation)::

        int2bytes(n:int, chunk_size:int) : string

    .. WARNING:
        Does not preserve leading zeros if you don't specify a chunk size.

    Usage::
    
        >>> int2bytes(123456789)
        b'\x07[\xcd\x15'
        >>> bytes2int(int2bytes(123456789))
        123456789

        >>> int2bytes(123456789, 6)
        b'\x00\x00\x07[\xcd\x15'
        >>> bytes2int(int2bytes(123456789, 128))
        123456789

        >>> int2bytes(123456789, 3)
        Traceback (most recent call last):
        ...
        OverflowError: Need 4 bytes for number, but chunk size is 3

    :param number:
        Integer value
    :param chunk_size:
        If optional chunk size is given and greater than zero, pad the front of
        the byte string with binary zeros so that the length is a multiple of
        ``chunk_size``. Raises an OverflowError if the chunk_size is not
        sufficient to represent the integer.
    :returns:
        Raw bytes (base-256 representation).
    :raises:
        ``OverflowError`` when block_size is given and the number takes up more
        bytes than fit into the block.
    """
    if number < 0:
        raise ValueError('Number must be unsigned integer: %d' % number)

    raw_bytes = b('')
    if not number:
        # 0 == '\x00'
        raw_bytes = _zero_byte

    # Align packing to machine word size.
    num = number
    word_bits, word_bytes, max_uint, pack_type = _get_machine_alignment(num)
    pack_format = ">" + pack_type
    while num > 0:
        raw_bytes = pack(pack_format, num & max_uint) + raw_bytes
        num >>= word_bits

    # Count the number of zero prefix bytes.
    zero_leading = 0
    for zero_leading, x in enumerate(raw_bytes):
        if x != _zero_byte[0]:
            break

    if chunk_size > 0:
        # Bounds checking. We're not doing this up-front because the
        # most common use case is not specifying a chunk size. In the worst
        # case, the number will already have been converted to bytes above.
        length = len(raw_bytes) - zero_leading
        if length > chunk_size:
            raise OverflowError(
                "Need %d bytes for number, but chunk size is %d" %
                (length, chunk_size)
            )
        remainder = length % chunk_size
        if remainder:
            padding_size = (chunk_size - remainder)
            if zero_leading > 0:
                raw_bytes = raw_bytes[zero_leading-padding_size:]
            else:
                raw_bytes = (padding_size * _zero_byte) + raw_bytes
    else:
        raw_bytes = raw_bytes[zero_leading:]
    return raw_bytes


if __name__ == '__main__':
    import doctest
    doctest.testmod()


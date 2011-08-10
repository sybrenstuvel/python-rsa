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

'''Python compatibility wrappers.'''


from __future__ import absolute_import

from struct import pack

try:
    # < Python3
    unicode_type = unicode
    have_python3 = False
except NameError:
    # Python3.
    unicode_type = str
    have_python3 = True

# Fake byte literals.
if str is unicode_type:
    def byte_literal(s):
        return s.encode('latin1')
else:
    def byte_literal(s):
        return s

# ``long`` is no more. Do type detection using this instead.
try:
    integer_types = (int, long)
except NameError:
    integer_types = (int,)

b = byte_literal

try:
    # Python 2.6 or higher.
    bytes_type = bytes
except NameError:
    # Python 2.5
    bytes_type = str


def is_bytes(obj):
    """
    Determines whether the given value is a byte string.

    :param obj:
        The value to test.
    :returns:
        ``True`` if ``value`` is a byte string; ``False`` otherwise.
    """
    return isinstance(obj, bytes_type)


def is_integer(obj):
    """
    Determines whether the given value is an integer.

    :param obj:
        The value to test.
    :returns:
        ``True`` if ``value`` is an integer; ``False`` otherwise.
    """
    return isinstance(obj, integer_types)


def byte(num):
    """
    Converts a number between 0 and 255 (both inclusive) to a base-256 (byte)
    representation.

    Use it as a replacement for ``chr`` where you are expecting a byte
    because this will work on all current versions of Python::

        >>> byte(0)
        '\x00'
        >>> byte(255)
        '\xff'

    :param num:
        An unsigned integer between 0 and 255 (both inclusive).
    :returns:
        A single byte.
    """
    return pack("B", num)

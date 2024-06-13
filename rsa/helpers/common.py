#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Common functionality shared by several modules."""

import math
import typing
import logging
import rsa.helpers.decorators as decorators

import sympy

logger = logging.getLogger(__name__)


@decorators.log_decorator(logger)
def bit_size(num: int) -> int:
    """
    Number of bits needed to represent a integer excluding any prefix
    0 bits.

    Usage::

        >>> bit_size(1023)
        10
        >>> bit_size(1024)
        11
        >>> bit_size(1025)
        11

    :param num:
        Integer value. If num is 0, returns 0. Only the absolute value of the
        number is considered. Therefore, signed integers will be abs(num)
        before the number's bit length is determined.
    :returns:
        Returns the number of bits in the integer.
    """

    try:
        return num.bit_length()
    except AttributeError as ex:
        raise TypeError("bit_size(num) only supports integers, not %r" % type(num)) from ex


@decorators.log_decorator(logger)
def byte_size(number: int) -> int:
    """
    Returns the number of bytes required to hold a specific long number.

    The number of bytes is rounded up.

    Usage::

        >>> byte_size(1 << 1023)
        128
        >>> byte_size((1 << 1024) - 1)
        128
        >>> byte_size(1 << 1024)
        129

    :param number:
        An unsigned integer
    :returns:
        The number of bytes required to hold a specific long number.
    """
    return 1 if number == 0 else math.ceil(bit_size(number) / 8)


@decorators.log_decorator(logger)
def inverse(x: int, n: int) -> int:
    """Returns the inverse of x % n under multiplication, a.k.a x^-1 (mod n)

    >>> inverse(7, 4)
    3
    >>> (inverse(143, 4) * 143) % 4
    1
    """
    return int(sympy.mod_inverse(x, n))


@decorators.log_decorator(logger)
def chinese_remainder_theorem(remainders: typing.Iterable[int], moduli: typing.Iterable[int]) -> int:
    """Chinese Remainder Theorem.

    Calculates x such that x = remainders[i] (mod moduli[i]) for each i.

    :param remainders: the remainders of the equations
    :param moduli: the moduli of the equations
    :returns: x such that x = remainders[i] (mod moduli[i]) for each i

    >>> chinese_remainder_theorem([2, 3], [3, 5])
    8

    >>> chinese_remainder_theorem([2, 3, 2], [3, 5, 7])
    23

    >>> chinese_remainder_theorem([2, 3, 0], [7, 11, 15])
    135
    """

    total_modulus = sympy.prod(moduli, start=1)
    solution = 0

    # Apply the Chinese Remainder Theorem formula
    for modulus, remainder in zip(moduli, remainders):
        partial_modulus = total_modulus // modulus
        inverse_partial = inverse(partial_modulus, modulus)

        solution = (solution + remainder * partial_modulus * inverse_partial) % total_modulus

    return solution


if __name__ == "__main__":
    import doctest

    doctest.testmod()

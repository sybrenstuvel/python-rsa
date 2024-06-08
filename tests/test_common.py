#!/usr/bin/env python
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

import pytest
import typing
from rsa.helpers import byte_size, bit_size, inverse


@pytest.mark.parametrize("value, expected", [
    (1 << 1023, 128),
    ((1 << 1024) - 1, 128),
    (1 << 1024, 129),
    (255, 1),
    (256, 2),
    (0xFFFF, 2),
    (0xFFFFFF, 3),
    (0xFFFFFFFF, 4),
    (0xFFFFFFFFFF, 5),
    (0xFFFFFFFFFFFF, 6),
    (0xFFFFFFFFFFFFFF, 7),
    (0xFFFFFFFFFFFFFFFF, 8),
])
def test_byte_size_values(value: int, expected: int) -> None:
    assert byte_size(value) == expected


def test_byte_size_zero() -> None:
    assert byte_size(0) == 1


@pytest.mark.parametrize("bad_value", [
    [], (), {}, "", None
])
def test_byte_size_bad_type(bad_value: typing.Any) -> None:
    with pytest.raises(TypeError):
        byte_size(bad_value)


def test_bit_size_zero() -> None:
    assert bit_size(0) == 0


@pytest.mark.parametrize("value, expected", [
    (1023, 10),
    (1024, 11),
    (1025, 11),
    (1 << 1024, 1025),
    ((1 << 1024) + 1, 1025),
    ((1 << 1024) - 1, 1024),
])
def test_bit_size_values(value: int, expected: int) -> None:
    assert bit_size(value) == expected


@pytest.mark.parametrize("value, expected", [
    (-1023, 10),
    (-1024, 11),
    (-1025, 11),
    (-1 << 1024, 1025),
    (-((1 << 1024) + 1), 1025),
    (-((1 << 1024) - 1), 1024),
])
def test_bit_size_negative_values(value: int, expected: int) -> None:
    assert bit_size(value) == expected


@pytest.mark.parametrize("a, b, expected", [
    (7, 4, 3),
    (5, 11, 9),
])
def test_inverse_normal(a: int, b: int, expected: int) -> None:
    assert inverse(a, b) == expected


@pytest.mark.parametrize("a, b", [
    (4, 8),
    (25, 5),
])
def test_inverse_not_relative_prime(a: int, b: int) -> None:
    with pytest.raises(ValueError):
        inverse(a, b)

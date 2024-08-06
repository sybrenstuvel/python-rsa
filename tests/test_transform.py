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
from rsa.helpers.transform import int2bytes, bytes2int


def test_int2bytes_accuracy():
    assert int2bytes(123456789) == b"\x07[\xcd\x15"


def test_int2bytes_codec_identity():
    assert bytes2int(int2bytes(123456789, 128)) == 123456789


def test_int2bytes_chunk_size():
    assert int2bytes(123456789, 6) == b"\x00\x00\x07[\xcd\x15"
    assert int2bytes(123456789, 7) == b"\x00\x00\x00\x07[\xcd\x15"


def test_int2bytes_zero():
    assert int2bytes(0, 4) == b"\x00" * 4
    assert int2bytes(0, 7) == b"\x00" * 7
    assert int2bytes(0) == b"\x00"


def test_int2bytes_correctness_against_base_implementation():
    values = [
        1 << 512,
        1 << 8192,
        1 << 77,
    ]
    for value in values:
        assert bytes2int(int2bytes(value)) == value, f"Boom {value}"


def test_int2bytes_raises_overflow_error_when_chunk_size_is_insufficient():
    with pytest.raises(OverflowError):
        int2bytes(123456789, 3)
    with pytest.raises(OverflowError):
        int2bytes(299999999999, 4)


def test_int2bytes_raises_value_error_when_negative_integer():
    with pytest.raises(ValueError):
        int2bytes(-1)


def test_int2bytes_raises_type_error_when_not_integer():
    with pytest.raises(TypeError):
        int2bytes(None)

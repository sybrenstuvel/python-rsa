# -*- coding: utf-8 -*-
#
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

"""Functions for generating random numbers."""

# Source inspired by code by Yesudeep Mangalapilly <yesudeep@gmail.com>

import os

from rsa import common, transform
from rsa._compat import byte


def randint(start,end):
    """Returns a random integer x with start <= x < end
    """
    assert end>start
    span=end-start
    #get an int with 64 extra bits
    bytes=(common.bit_size(span)+7)//8+8
    value = transform.bytes2int(os.urandom(bytes))
    #mod by the span to create a uniform distribution
    return start+value%span
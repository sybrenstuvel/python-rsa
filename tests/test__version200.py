#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest2
from rsa._compat import b

from rsa._version200 import int2bytes, bytes2int

class Test_int2bytes(unittest2.TestCase):
    def test_values(self):
        self.assertEqual(int2bytes(123456789), b('\x07[\xcd\x15'))
        self.assertEqual(bytes2int(int2bytes(123456789)), 123456789)

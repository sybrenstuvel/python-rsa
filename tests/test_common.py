#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest2
import struct
from rsa._compat import byte, b
from rsa.common import byte_size, bit_size, _bit_size


class Test_byte(unittest2.TestCase):
    def test_values(self):
        self.assertEqual(byte(0), b('\x00'))
        self.assertEqual(byte(255), b('\xff'))

    def test_struct_error_when_out_of_bounds(self):
        self.assertRaises(struct.error, byte, 256)
        self.assertRaises(struct.error, byte, -1)


class Test_byte_size(unittest2.TestCase):
    def test_values(self):
        self.assertEqual(byte_size(1 << 1023), 128)
        self.assertEqual(byte_size((1 << 1024) - 1), 128)
        self.assertEqual(byte_size(1 << 1024), 129)

    def test_zero(self):
        self.assertEqual(byte_size(0), 0)

    def test_bad_type(self):
        self.assertRaises(TypeError, byte_size, [])
        self.assertRaises(TypeError, byte_size, ())
        self.assertRaises(TypeError, byte_size, dict())
        self.assertRaises(TypeError, byte_size, "")
        self.assertRaises(TypeError, byte_size, None)

class Test_bit_size(unittest2.TestCase):
    def test_zero(self):
        self.assertEqual(bit_size(0), 0)

    def test_values(self):
        self.assertEqual(bit_size(1023), 10)
        self.assertEqual(bit_size(1024), 11)
        self.assertEqual(bit_size(1025), 11)
        self.assertEqual(bit_size(1 << 1024), 1025)
        self.assertEqual(bit_size((1 << 1024) + 1), 1025)
        self.assertEqual(bit_size((1 << 1024) - 1), 1024)

        self.assertEqual(_bit_size(1023), 10)
        self.assertEqual(_bit_size(1024), 11)
        self.assertEqual(_bit_size(1025), 11)
        self.assertEqual(_bit_size(1 << 1024), 1025)
        self.assertEqual(_bit_size((1 << 1024) + 1), 1025)
        self.assertEqual(_bit_size((1 << 1024) - 1), 1024)

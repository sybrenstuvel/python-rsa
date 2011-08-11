# -*- coding: utf-8 -*-


import unittest2
from rsa._compat import b
from rsa.transform import int2bytes, old_int2bytes


class Test_integer_to_bytes(unittest2.TestCase):
    def test_chunk_size(self):
        self.assertEqual(int2bytes(123456789, 6),
                         b('\x00\x00\x07[\xcd\x15'))
        self.assertEqual(int2bytes(123456789, 7),
                         b('\x00\x00\x00\x07[\xcd\x15'))
        self.assertEqual(old_int2bytes(123456789, 6),
                         b('\x00\x00\x07[\xcd\x15'))
        self.assertEqual(old_int2bytes(123456789, 7),
                         b('\x00\x00\x00\x07[\xcd\x15'))

    def test_raises_OverflowError_when_chunk_size_is_insufficient(self):
        self.assertRaises(OverflowError, int2bytes, 123456789, 3)
        self.assertRaises(OverflowError, int2bytes, 299999999999, 4)
        self.assertRaises(OverflowError, old_int2bytes, 123456789, 3)
        self.assertRaises(OverflowError, old_int2bytes, 299999999999, 4)

    def test_raises_ValueError_when_negative_integer(self):
        self.assertRaises(ValueError, int2bytes, -1)
        self.assertRaises(ValueError, old_int2bytes, -1)

    def test_raises_TypeError_when_not_integer(self):
        self.assertRaises(TypeError, int2bytes, None)
        self.assertRaises(TypeError, old_int2bytes, None)

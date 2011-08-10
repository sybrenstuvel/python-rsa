'''Tests varblock operations.'''

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import unittest

import rsa
from rsa import varblock

class VarintTest(unittest.TestCase):

    def test_read_varint(self):
        
        encoded = '\xac\x02crummy'
        infile = StringIO(encoded)

        (decoded, read) = varblock.read_varint(infile)

        # Test the returned values
        self.assertEqual(300, decoded)
        self.assertEqual(2, read)

        # The rest of the file should be untouched
        self.assertEqual('crummy', infile.read())

    def test_read_zero(self):
        
        encoded = '\x00crummy'
        infile = StringIO(encoded)

        (decoded, read) = varblock.read_varint(infile)

        # Test the returned values
        self.assertEqual(0, decoded)
        self.assertEqual(1, read)

        # The rest of the file should be untouched
        self.assertEqual('crummy', infile.read())

    def test_write_varint(self):
        
        expected = '\xac\x02'
        outfile = StringIO()

        written = varblock.write_varint(outfile, 300)

        # Test the returned values
        self.assertEqual(expected, outfile.getvalue())
        self.assertEqual(2, written)


    def test_write_zero(self):
        
        outfile = StringIO()
        written = varblock.write_varint(outfile, 0)

        # Test the returned values
        self.assertEqual('\x00', outfile.getvalue())
        self.assertEqual(1, written)


class VarblockTest(unittest.TestCase):

    def test_yield_varblock(self):
        infile = StringIO('\x01\x0512345\x06Sybren')

        varblocks = list(varblock.yield_varblocks(infile))
        self.assertEqual(['12345', 'Sybren'], varblocks)

class FixedblockTest(unittest.TestCase):

    def test_yield_fixedblock(self):

        infile = StringIO('123456Sybren')

        fixedblocks = list(varblock.yield_fixedblocks(infile, 6))
        self.assertEqual(['123456', 'Sybren'], fixedblocks)


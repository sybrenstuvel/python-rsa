'''Tests block operations.'''

from StringIO import StringIO
import unittest

import rsa
from rsa import bigfile, varblock

class BigfileTest(unittest.TestCase):

    def test_encrypt_decrypt_bigfile(self):

        # Expected block size + 11 bytes padding
        pub_key, priv_key = rsa.newkeys((6 + 11) * 8)

        # Encrypt the file
        message = '123456Sybren'
        infile = StringIO(message)
        outfile = StringIO()

        bigfile.encrypt_bigfile(infile, outfile, pub_key)

        # Test
        crypto = outfile.getvalue()

        cryptfile = StringIO(crypto)
        clearfile = StringIO()

        bigfile.decrypt_bigfile(cryptfile, clearfile, priv_key)
        self.assertEquals(clearfile.getvalue(), message)
        
        # We have 2x6 bytes in the message, so that should result in two
        # bigfile.
        cryptfile.seek(0)
        varblocks = list(varblock.yield_varblocks(cryptfile))
        self.assertEqual(2, len(varblocks))


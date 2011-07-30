'''Tests string operations.'''

import unittest

import rsa

class StringTest(unittest.TestCase):

    def setUp(self):
        (self.pub, self.priv) = rsa.newkeys(384)

    def test_enc_dec(self):

        message = u"Euro=\u20ac ABCDEFGHIJKLMNOPQRSTUVWXYZ".encode('utf-8')
        print "\tMessage:   %s" % message

        encrypted = rsa.encrypt(message, self.pub)
        print "\tEncrypted: %s" % encrypted

        decrypted = rsa.decrypt(encrypted, self.priv)
        print "\tDecrypted: %s" % decrypted

        self.assertEqual(message, decrypted)


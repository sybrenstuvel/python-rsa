'''Tests string operations.'''

import struct
import unittest

import rsa
from rsa import pkcs1

class BinaryTest(unittest.TestCase):

    def setUp(self):
        (self.pub, self.priv) = rsa.newkeys(256)

    def test_enc_dec(self):

        message = struct.pack('>IIII', 0, 0, 0, 1) + 5 * '\x00'
        print "\tMessage:   %r" % message

        encrypted = pkcs1.encrypt(message, self.pub)
        print "\tEncrypted: %r" % encrypted

        decrypted = pkcs1.decrypt(encrypted, self.priv)
        print "\tDecrypted: %r" % decrypted

        self.assertEqual(message, decrypted)

#    def test_sign_verify(self):
#
#        message = struct.pack('>IIII', 0, 0, 0, 1) + 20 * '\x00'
#        print "\tMessage:   %r" % message
#
#        signed = rsa.sign(message, self.priv)
#        print "\tSigned:    %r" % signed
#
#        verified = rsa.verify(signed, self.pub)
#        print "\tVerified:  %r" % verified
#
#        self.assertEqual(message, verified)

'''Tests string operations.'''

import struct
import unittest

import rsa
from rsa import pkcs1

class BinaryTest(unittest.TestCase):

    def setUp(self):
        (self.pub, self.priv) = rsa.newkeys(256)

    def test_enc_dec(self):

        message = struct.pack('>IIII', 0, 0, 0, 1)
        print "\tMessage:   %r" % message

        encrypted = pkcs1.encrypt(message, self.pub)
        print "\tEncrypted: %r" % encrypted

        decrypted = pkcs1.decrypt(encrypted, self.priv)
        print "\tDecrypted: %r" % decrypted

        self.assertEqual(message, decrypted)

    def test_decoding_failure(self):

        message = struct.pack('>IIII', 0, 0, 0, 1)
        encrypted = pkcs1.encrypt(message, self.pub)

        # Alter the encrypted stream
        encrypted = encrypted[:5] + chr(ord(encrypted[5]) + 1) + encrypted[6:]
        
        self.assertRaises(ValueError, pkcs1.decrypt, encrypted, self.priv)

    def test_randomness(self):
        '''Encrypting the same message twice should result in different
        cryptos.
        '''
        
        message = struct.pack('>IIII', 0, 0, 0, 1)
        encrypted1 = pkcs1.encrypt(message, self.pub)
        encrypted2 = pkcs1.encrypt(message, self.pub)
        
        self.assertNotEqual(encrypted1, encrypted2)

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

#!/usr/bin/env python

'''Re-encryption demonstration

This little program shows how to re-encrypt crypto from versions older than 2.0.
Those versions were inherently insecure, and version 2.0 solves those
insecurities. This did result in a different crypto format, so it's not backward
compatible. Use this program as a demonstration on how to re-encrypt your
files/passwords/whatevers into the new format.
'''

import sys
import rsa
from rsa import _version133 as insecure

(pub, priv) = rsa.newkeys(64)

# Construct the encrypted content. You'd typically read an encrypted file or
# stream here.
cleartext = 'Give me more cowbell'
old_crypto = insecure.encrypt(cleartext, pub)
print 'Old crypto:', old_crypto
print

# Decrypt and re-encrypt the contents to make it compatible with the new RSA
# module.
decrypted = insecure.decrypt(old_crypto, priv)
new_crypto = rsa.encrypt(decrypted, pub)

print 'New crypto:', new_crypto
print


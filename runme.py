#!/usr/bin/python

import sys
import rsa

from rsa import key

pub = key.PublicKey(31698122414741849421263704398157795847591, 65537)

priv = key.PrivateKey(31698122414741849421263704398157795847591, 65537,
    7506520894712811128876594754922157377793, 4169414332984308880603,
    7602535963858869797)

print "Running rsa.verify(verslag, pub)..."

crypto = open('verslag.crypt').read()
verslag = rsa.verify(crypto, pub)

print "Decryption done, press enter to read"
sys.stdin.readline()
print verslag

print "Generating public & private keypair for demonstrational purposes..."
(pub, priv) = rsa.newkeys(256)

print
print "Public:"
print "\te: %d" % pub['e']
print "\tn: %d" % pub['n']
print

print "Private:"
print "\td: %d" % priv['d']
print "\tp: %d" % priv['p']
print "\tq: %d" % priv['q']


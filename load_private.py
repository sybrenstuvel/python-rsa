#!/usr/bin/env python

import logging

logging.basicConfig(level=logging.DEBUG)

from rsa import pkcs1, key

# pick q, pick p
# [1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 4, 5, 5, 6, 7, 10, 14, 23, 46]
# Median:  2
# Average: 6.8

# pick p, pick q
# [1, 1, 2, 3, 3, 3, 4, 5, 5, 7, 7, 9, 10, 13, 14, 15, 16, 16, 23, 49]
# Median:  7
# Average: 10.3

# pick both
# [1, 1, 2, 2, 2, 3, 4, 4, 4, 5, 5, 5, 5, 6, 7, 8, 10, 13, 14, 21]
# Median:  5
# Average: 6.1



tries = [key.find_p_q(512) for _ in range(20)]
tries = sorted(tries)
print tries
print 'Median: ', tries[len(tries) // 2]
print 'Average:', sum(tries) / float(len(tries))

#(pub_key, priv_key) = key.newkeys(1024)
#
#print priv_key
#
#with open('mykey.pem', 'w') as mykey:
#    mykey.write(priv_key.save_pkcs1_pem())

#with open('mykey.der', 'w') as mykey:
#    mykey.write(priv_key.save_pkcs1_der())



# Write the message file
#message = 'je moeder\n'
#with open('message.txt', 'w') as out:
#    out.write(message)

# Encrypt the message
#msg = pkcs1.encrypt(message, pub_key)
#with open('message.rsa', 'w') as out:
#    out.write(msg)

# Sign the message
#signature = pkcs1.sign(message, priv_key, 'SHA-256')
#with open('message.sig', 'w') as out:
#    out.write(signature)



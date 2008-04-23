import rsa

(pub, priv) = rsa.gen_pubpriv_keys(64)

print "Testing integer operations:"

message = 42
print "\tMessage:   %d" % message

encrypted = rsa.encrypt_int(message, pub['e'], pub['n'])
print "\tEncrypted: %d" % encrypted

decrypted = rsa.decrypt_int(encrypted, priv['d'], pub['n'])
print "\tDecrypted: %d" % decrypted

signed = rsa.sign_int(message,priv['d'], pub['n'])
print "\tSigned:    %d" % signed

verified = rsa.verify_int(signed, pub['e'],pub['n'])
print "\tVerified:  %d" % verified


print "Testing string operations:"

message = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
print "\tMessage:   %s" % message

encrypted = rsa.encrypt(message, pub)
print "\tEncrypted: %s" % encrypted

decrypted = rsa.decrypt(encrypted, priv)
print "\tDecrypted: %s" % decrypted

signed = rsa.sign(message,priv)
print "\tSigned:    %s" % signed

verified = rsa.verify(signed, pub)
print "\tVerified:  %s" % verified

'''Functions for PKCS1 version 1.5 encryption and signing

This module implements certain functionality from PKCS1 version 1.5. For a
very clear example, read http://www.di-mgt.com.au/rsa_alg.html#pkcs1schemes

At least 8 bytes of random padding is used when encrypting a message. This makes
these methods much more secure than the ones in the ``rsa`` module.

WARNING: this module leaks information when decryption or verification fails.
The exceptions that are raised contain the Python traceback information, which
can be used to deduce where in the process the failure occurred. DO NOT PASS
SUCH INFORMATION to your users.
'''

import hashlib
import os

from rsa import common, transform, core

# ASN.1 codes that describe the hash algorithm used.
HASH_ASN1 = {
    'MD5': '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
    'SHA-1': '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
    'SHA-256': '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    'SHA-384': '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    'SHA-512': '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

HASH_METHODS = {
    'MD5': hashlib.md5,
    'SHA-1': hashlib.sha1,
    'SHA-256': hashlib.sha256,
    'SHA-384': hashlib.sha384,
    'SHA-512': hashlib.sha512,
}

class CryptoError(Exception):
    '''Base class for all exceptions in this module.'''

class DecryptionError(CryptoError):
    '''Raised when decryption fails.'''

class VerificationError(CryptoError):
    '''Raised when verification fails.'''
 
def _pad_for_encryption(message, target_length):
    r'''Pads the message for encryption, returning the padded message.
    
    @return: 00 02 RANDOM_DATA 00 MESSAGE
    
    >>> block = _pad_for_encryption('hello', 16)
    >>> len(block)
    16
    >>> block[0:2]
    '\x00\x02'
    >>> block[-6:]
    '\x00hello'

    '''

    max_msglength = target_length - 11
    msglength = len(message)
    
    if msglength > max_msglength:
        raise OverflowError('%i bytes needed for message, but there is only'
            ' space for %i' % (msglength, max_msglength))
    
    # Get random padding
    padding = ''
    padding_length = target_length - msglength - 3
    
    # We remove 0-bytes, so we'll end up with less padding than we've asked for,
    # so keep adding data until we're at the correct length.
    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)
        
        # Always read at least 8 bytes more than we need, and trim off the rest
        # after removing the 0-bytes. This increases the chance of getting
        # enough bytes, especially when needed_bytes is small
        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace('\x00', '')
        padding = padding + new_padding[:needed_bytes]
    
    assert len(padding) == padding_length
    
    return ''.join(['\x00\x02',
                    padding,
                    '\x00',
                    message])
    

def _pad_for_signing(message, target_length):
    r'''Pads the message for signing, returning the padded message.
    
    The padding is always a repetition of FF bytes.
    
    @return: 00 01 PADDING 00 MESSAGE
    
    >>> block = _pad_for_signing('hello', 16)
    >>> len(block)
    16
    >>> block[0:2]
    '\x00\x01'
    >>> block[-6:]
    '\x00hello'
    >>> block[2:-6]
    '\xff\xff\xff\xff\xff\xff\xff\xff'
    
    '''

    max_msglength = target_length - 11
    msglength = len(message)
    
    if msglength > max_msglength:
        raise OverflowError('%i bytes needed for message, but there is only'
            ' space for %i' % (msglength, max_msglength))
    
    padding_length = target_length - msglength - 3
    
    return ''.join(['\x00\x01',
                    padding_length * '\xff',
                    '\x00',
                    message])
    
    
def encrypt(message, pub_key):
    '''Encrypts the given message using PKCS1 v1.5
    
    @param message: the message to encrypt. Must be a byte string no longer than
        ``k-11`` bytes, where ``k`` is the number of bytes needed to encode
        the ``n`` component of the public key.
    @param pub_key: the public key to encrypt with.
    
    @raise OverflowError: when the message is too large to fit in the padded
        block.
        
    >>> from rsa import keygen, common
    >>> (pub_key, priv_key) = keygen.newkeys(256)
    >>> message = 'hello'
    >>> crypto = encrypt(message, pub_key)
    
    The crypto text should be just as long as the public key 'n' component:
    >>> len(crypto) == common.byte_size(pub_key['n'])
    True
    
    '''
    
    keylength = common.byte_size(pub_key['n'])
    padded = _pad_for_encryption(message, keylength)
    
    payload = transform.bytes2int(padded)
    encrypted = core.encrypt_int(payload, pub_key['e'], pub_key['n'])
    block = transform.int2bytes(encrypted, keylength)
    
    return block

def decrypt(crypto, priv_key):
    r'''Decrypts the given message using PKCS1 v1.5
    
    The decryption is considered 'failed' when the resulting cleartext doesn't
    start with the bytes 00 02, or when the 00 byte between the padding and
    the message cannot be found.
    
    @param crypto: the crypto text as returned by ``encrypt(message, pub_key)``
    @param priv_key: the private key to decrypt with.
    
    @raise DecryptionError: when the decryption fails. No details are given as
        to why the code thinks the decryption fails, as this would leak
        information about the private key.

    >>> from rsa import keygen, common
    >>> (pub_key, priv_key) = keygen.newkeys(256)

    It works with strings:
    >>> decrypt(encrypt('hello', pub_key), priv_key)
    'hello'
    
    And with binary data:
    >>> decrypt(encrypt('\x00\x00\x00\x00\x01', pub_key), priv_key)
    '\x00\x00\x00\x00\x01'
    
    '''
    
    blocksize = common.byte_size(priv_key['n']) 
    encrypted = transform.bytes2int(crypto)
    decrypted = core.decrypt_int(encrypted, priv_key['d'], priv_key['n'])
    cleartext = transform.int2bytes(decrypted, blocksize)

    # If we can't find the cleartext marker, decryption failed.
    if cleartext[0:2] != '\x00\x02':
        raise DecryptionError('Decryption failed')
    
    # Find the 00 separator between the padding and the message
    try:
        sep_idx = cleartext.index('\x00', 2)
    except ValueError:
        raise DecryptionError('Decryption failed')
    
    return cleartext[sep_idx+1:]
    
def sign(message, priv_key, hash):
    '''Signs the message with the private key.

    Hashes the message, then signs the hash with the given key. This is known
    as a "detached signature", because the message itself isn't signed.
    
    @param message: the message to sign
    @param priv_key: the private key to sign with
    @param hash: the hash method used on the message. Use 'MD5', 'SHA-1',
        'SHA-256', 'SHA-384' or 'SHA-512'.
    
    @return: a message signature block.
    
    @raise OverflowError: if the private key is too small to contain the
        requested hash.

    '''

    # Get the ASN1 code for this hash method
    if hash not in HASH_ASN1:
        raise ValueError('Invalid hash method: %s' % hash)
    asn1code = HASH_ASN1[hash]
    
    # Calculate the hash
    hash = _hash(message, hash)

    # Encrypt the hash with the private key
    cleartext = asn1code + hash
    keylength = common.byte_size(priv_key['n'])
    padded = _pad_for_signing(cleartext, keylength)
    
    payload = transform.bytes2int(padded)
    encrypted = core.encrypt_int(payload, priv_key['d'], priv_key['n'])
    block = transform.int2bytes(encrypted, keylength)
    
    return block

def verify(message, signature, pub_key):
    '''Verifies that the signature matches the message.
    
    The hash method is detected automatically from the signature.
    
    @param message: the signed message
    @param signature: the signature block, as created with ``sign(...)``.
    @param pub_key: the public key of the person signing the message.
    
    @raise VerificationError: when the signature doesn't match the message.
    '''
    
    blocksize = common.byte_size(pub_key['n']) 
    encrypted = transform.bytes2int(signature)
    decrypted = core.decrypt_int(encrypted, pub_key['e'], pub_key['n'])
    clearsig = transform.int2bytes(decrypted, blocksize)

    # If we can't find the signature  marker, verification failed.
    if clearsig[0:2] != '\x00\x01':
        raise VerificationError('Verification failed')
    
    # Find the 00 separator between the padding and the payload
    try:
        sep_idx = clearsig.index('\x00', 2)
    except ValueError:
        raise VerificationError('Verification failed')
    
    # Get the hash and the hash method
    (method_name, signature_hash) = _find_method_hash(clearsig[sep_idx+1:])
    message_hash = _hash(message, method_name)

    # Compare the real hash to the hash in the signature
    if message_hash != signature_hash:
        raise VerificationError('Verification failed')

def _hash(message, method_name):
    '''Returns the message digest.'''

    if method_name not in HASH_METHODS:
        raise ValueError('Invalid hash method: %s' % method_name)
    
    method = HASH_METHODS[method_name]
    hasher = method()
    hasher.update(message)
    return hasher.digest()


def _find_method_hash(method_hash):
    '''Finds the hash method and the hash itself.
    
    @param method_hash: ASN1 code for the hash method concatenated with the
        hash itself.
    
    @return: tuple (method, hash) where ``method`` is the used hash method, and
        ``hash`` is the hash itself.
    
    @raise VerificationFailed: when the hash method cannot be found
    '''

    for (hashname, asn1code) in HASH_ASN1.iteritems():
        if not method_hash.startswith(asn1code):
            continue
        
        return (hashname, method_hash[len(asn1code):])
    
    raise VerificationError('Verification failed')


__all__ = ['encrypt', 'decrypt', 'sign', 'verify',
           'DecryptionError', 'VerificationError', 'CryptoError']

if __name__ == '__main__':
    print 'Running doctests 1000x or until failure'
    import doctest
    
    for count in range(1000):
        (failures, tests) = doctest.testmod()
        if failures:
            break
        
        if count and count % 100 == 0:
            print '%i times' % count
    
    print 'Doctests done'

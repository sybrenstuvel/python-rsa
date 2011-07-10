'''Functions for PKCS1 version 1.5

This module implements certain functionality from PKCS1 version 1.5. For a
very clear example, read http://www.di-mgt.com.au/rsa_alg.html#pkcs1schemes

At least 8 bytes of random padding is used when encrypting a message. This makes
these methods much more secure than the ones in the ``rsa`` module.

'''

import os

from rsa import common, transform, core


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
    
    @raise ValueError: when the decryption fails. No details are given as to why
        the code thinks the decryption fails, as this would leak information
        about the private key.

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
        raise ValueError('Decryption failed')
    
    # Find the 00 separator between the padding and the message
    try:
        sep_idx = cleartext.index('\x00', 2)
    except ValueError:
        raise ValueError('Decryption failed')
    
    return cleartext[sep_idx+1:]
    

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

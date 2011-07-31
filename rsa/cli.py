# -*- coding: utf-8 -*-
#
#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

'''Commandline scripts.

'''

import sys
from optparse import OptionParser

import rsa
import rsa.bigfile

def keygen():
    # Parse the CLI options
    parser = OptionParser(usage='usage: %prog [options] keysize',
            description='Generates a new RSA keypair of "keysize" bits.')
    
    parser.add_option('--pubout', type='string',
            help='Output filename for the public key. The public key is '
            'not saved if this option is not present. You can use '
            'pyrsa-priv2pub to create the public key file later.')
    
    parser.add_option('--privout', type='string',
            help='Output filename for the private key. The key is '
            'written to stdout if this option is not present.')

    parser.add_option('--form',
            help='key format of the private and public keys - default PEM',
            choices=('PEM', 'DER'), default='PEM')

    (cli, cli_args) = parser.parse_args(sys.argv[1:])

    if len(cli_args) != 1:
        parser.print_help()
        raise SystemExit(1)
    
    try:
        keysize = int(cli_args[0])
    except ValueError:
        parser.print_help()
        print >>sys.stderr, 'Not a valid number: %s' % cli_args[0]
        raise SystemExit(1)

    print >>sys.stderr, 'Generating %i-bit key' % keysize
    (pub_key, priv_key) = rsa.newkeys(keysize)


    # Save public key
    if cli.pubout:
        print >>sys.stderr, 'Writing public key to %s' % cli.pubout
        data = pub_key.save_pkcs1(format=cli.form)
        with open(cli.pubout, 'w') as outfile:
            outfile.write(data)

    # Save private key
    data = priv_key.save_pkcs1(format=cli.form)
    
    if cli.privout:
        print >>sys.stderr, 'Writing private key to %s' % cli.privout
        with open(cli.privout, 'w') as outfile:
            outfile.write(data)
    else:
        print >>sys.stderr, 'Writing private key to stdout'
        sys.stdout.write(data)


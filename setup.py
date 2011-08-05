#!/usr/bin/env python

# Ensure that a reasonably recent version of 'distribute' is installed.
from distribute_setup import use_setuptools
use_setuptools('0.6.10')

from setuptools import setup

import rsa

setup(name='rsa',
	version=rsa.__version__,
    description='Pure-Python RSA implementation', 
    author='Sybren A. Stuvel',
    author_email='sybren@stuvel.eu', 
    maintainer='Sybren A. Stuvel',
    maintainer_email='sybren@stuvel.eu',
	url='http://stuvel.eu/rsa',
	packages=['rsa'],
    license='ASL 2',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security :: Cryptography',
    ],
    install_requires=[
        'pyasn1 >= 0.0.13',
    ],
    entry_points={ 'console_scripts': [
        'pyrsa-priv2pub = rsa.util:private_to_public',
        'pyrsa-keygen = rsa.cli:keygen',
        'pyrsa-encrypt = rsa.cli:encrypt',
        'pyrsa-decrypt = rsa.cli:decrypt',
        'pyrsa-sign = rsa.cli:sign',
        'pyrsa-verify = rsa.cli:verify',
        'pyrsa-encrypt-bigfile = rsa.cli:encrypt_bigfile',
        'pyrsa-decrypt-bigfile = rsa.cli:decrypt_bigfile',
    ]},

)

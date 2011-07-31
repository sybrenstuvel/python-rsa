#!/usr/bin/env python

# Ensure that 'distribute' is installed.
from distribute_setup import use_setuptools
use_setuptools()

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
    license='GPL + EUPL',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'License :: OSI Approved :: European Union Public Licence 1.1 (EUPL 1.1)',
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
    ]},

)

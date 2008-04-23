#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(name='rsa',
	version='1.1',
    description='Pure-Python RSA implementation', 
    author=u'Sybren Stüvel'.encode('utf-8'), 
    author_email='sybren@stuvel.eu', 
    maintainer=u'Sybren Stüvel'.encode('utf-8'),
    maintainer_email='sybren@stuvel.eu',
	url='http://www.stuvel.eu/rsa',
	packages=['rsa'],
    license='GPL',
    classifiers=[
        'Development Status :: 5 - Beta',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Multimedia :: Graphics :: Capture :: Digital Camera',
        'Topic :: Artistic Software',
        'Natural Language :: English',
    ],
)

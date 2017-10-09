# -*- coding: utf-8 -*-
#
#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Functions for parallel computation on multiple cores.

Introduced in Python-RSA 3.1.

.. note::

    Requires Python 2.6 or newer.

"""

from __future__ import print_function

import multiprocessing as mp

from rsa._compat import range
import rsa.prime
import rsa.randnum


def _find_prime(nbits, pipe):
    while True:
        integer = rsa.randnum.read_random_odd_int(nbits)

        # Test for primeness
        if rsa.prime.is_prime(integer):
            pipe.send(integer)
            return


def getprime(nbits, poolsize):
    """Returns a prime number that can be stored in 'nbits' bits.

    Works in multiple threads at the same time.

    >>> p = getprime(128, 3)
    >>> rsa.prime.is_prime(p-1)
    False
    >>> rsa.prime.is_prime(p)
    True
    >>> rsa.prime.is_prime(p+1)
    False

    >>> from rsa import common
    >>> common.bit_size(p) == 128
    True

    """

    (pipe_recv, pipe_send) = mp.Pipe(duplex=False)

    # Create processes
    try:
        procs = [mp.Process(target=_find_prime, args=(nbits, pipe_send))
                 for _ in range(poolsize)]
        # Start processes
        for p in procs:
            p.start()

        result = pipe_recv.recv()
    finally:
        pipe_recv.close()
        pipe_send.close()

    # Terminate processes
    for p in procs:
        p.terminate()

    return result


def exec_parallel_curry(function,poolsize):
    """returns a multiprocess version of the supplied function for the given poolsize"""
    def retfunc(*args,**kwargs):
        return exec_parallel(poolsize,function,args,kwargs)
    return retfunc

def _do_work(pipe,function,args,kwargs):
    result=function(*args,**kwargs)
    pipe.send(result)

def exec_parallel(poolsize,function,args,kwargs):
    """
    carries out a function in multiple processes. Returns the first return value
    to be produced by any process
    """
    (pipe_recv, pipe_send) = mp.Pipe(duplex=False)

    # Create processes
    try:
        procs = [mp.Process(target=_do_work, args=(pipe_send,function,args,kwargs))
                 for _ in range(poolsize)]
        # Start processes
        for p in procs:
            p.start()

        result = pipe_recv.recv()
    finally:
        pipe_recv.close()
        pipe_send.close()

    # Terminate processes
    for p in procs:
        p.terminate()

    return result


__all__ = ['getprime','exec_parallel']

if __name__ == '__main__':
    print('Running doctests 1000x or until failure')
    import doctest

    for count in range(100):
        (failures, tests) = doctest.testmod()
        if failures:
            break

        if count and count % 10 == 0:
            print('%i times' % count)

    print('Doctests done')

#!/usr/bin/env python
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

import time
import functools
import typing

import rsa

if typing.TYPE_CHECKING:
    from rsa import PublicKey, PrivateKey

pool_size = 8
accurate = True


def timeit(func: typing.Callable) -> typing.Callable:
    """
    decorator for measuring the working time
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        elapsed_time = end_time - start_time
        return result, elapsed_time
    return wrapper


@timeit
def generate_keys(bit_size: int) -> typing.Tuple["PublicKey", "PrivateKey"]:
    """
    Generates a public key and private key for testing
    """
    return rsa.new_keys(bit_size, accurate=accurate, pool_size=pool_size)


def run_speed_test(bit_size: int) -> None:
    iterations = 0
    total_time = 0.0

    # At least a number of iterations, and at least 2 seconds
    while iterations < 10 or total_time < 2:
        _, elapsed_time = generate_keys(bit_size)
        iterations += 1
        total_time += elapsed_time

    dur_per_call = total_time / iterations

    print(f'{bit_size:5} bit: {dur_per_call:9.3f} sec. ({iterations} iterations over {total_time:.1f} seconds)')


def start_speed_test() -> None:
    for bit_size in (128, 256, 384, 512, 1024, 2048, 3072, 4096):
        run_speed_test(bit_size)


if __name__ == '__main__':
    start_speed_test()

#!/bin/sh
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

echo "int2bytes speed test"
echo "pypy"
pypy -mtimeit -s'from rsa.transform import int2bytes; n = 1<<4096' 'int2bytes(n)'
pypy -mtimeit -s'from rsa.transform import _int2bytes; n = 1<<4096' '_int2bytes(n)'
echo "python2.5"
python2.5 -mtimeit -s'from rsa.transform import int2bytes; n = 1<<4096' 'int2bytes(n)'
python2.5 -mtimeit -s'from rsa.transform import _int2bytes; n = 1<<4096' '_int2bytes(n)'
echo "python2.6"
python2.6 -mtimeit -s'from rsa.transform import int2bytes; n = 1<<4096' 'int2bytes(n, 516)'
python2.6 -mtimeit -s'from rsa.transform import _int2bytes; n = 1<<4096' '_int2bytes(n, 516)'
echo "python2.7"
python2.7 -mtimeit -s'from rsa.transform import int2bytes; n = 1<<4096' 'int2bytes(n)'
python2.7 -mtimeit -s'from rsa.transform import _int2bytes; n = 1<<4096' '_int2bytes(n)'
echo "python3.2"
python3 -mtimeit -s'from rsa.transform import int2bytes; n = 1<<4096' 'int2bytes(n)'
python3 -mtimeit -s'from rsa.transform import _int2bytes; n = 1<<4096' '_int2bytes(n)'

echo "bit_size speed test"
echo "python2.5"
python2.5 -mtimeit -s'from rsa.common import bit_size; n = 1<<4096' 'bit_size(n)'
python2.5 -mtimeit -s'from rsa.common import _bit_size; n = 1<<4096' '_bit_size(n)'
echo "python2.6"
python2.6 -mtimeit -s'from rsa.common import bit_size; n = 1<<4096' 'bit_size(n)'
python2.6 -mtimeit -s'from rsa.common import _bit_size; n = 1<<4096' '_bit_size(n)'
echo "python2.7"
python2.7 -mtimeit -s'from rsa.common import bit_size; n = 1<<4096' 'bit_size(n)'
python2.7 -mtimeit -s'from rsa.common import _bit_size; n = 1<<4096' '_bit_size(n)'
echo "python3.2"
python3 -mtimeit -s'from rsa.common import bit_size; n = 1<<4096' 'bit_size(n)'
python3 -mtimeit -s'from rsa.common import _bit_size; n = 1<<4096' '_bit_size(n)'
echo "pypy"
pypy -mtimeit -s'from rsa.common import bit_size; n = 1<<4096' 'bit_size(n)'
pypy -mtimeit -s'from rsa.common import _bit_size; n = 1<<4096' '_bit_size(n)'


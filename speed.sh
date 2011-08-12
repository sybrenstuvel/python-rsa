#!/bin/sh

echo "int2bytes speed test"
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


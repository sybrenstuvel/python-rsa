#!/usr/bin/env python
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

import unittest2
from rsa._compat import b
from rsa.pem import _markers


class Test__markers(unittest2.TestCase):
    def test_values(self):
        self.assertEqual(_markers('RSA PRIVATE KEY'),
            (b('-----BEGIN RSA PRIVATE KEY-----'),
             b('-----END RSA PRIVATE KEY-----')))

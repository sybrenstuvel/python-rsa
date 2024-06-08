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

"""ASN.1 definitions.

Not all ASN.1-handling code use these definitions, but when it does, they should be here.
"""


class CryptoError(Exception):
    """Base class for all exceptions in this module."""


class DecryptionError(CryptoError):
    """Raised when decryption fails."""


class VerificationError(CryptoError):
    """Raised when verification fails."""


class NotRelativePrimeError(ValueError):
    def __init__(self, a: int, b: int, d: int, msg: str = "") -> None:
        super().__init__(msg or "%d and %d are not relatively prime, divider=%i" % (a, b, d))
        self.a = a
        self.b = b
        self.d = d

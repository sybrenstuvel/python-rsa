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
"""RSA module

Module for calculating large primes, and RSA encryption, decryption, signing
and verification. Includes generating public and private keys.

WARNING: this implementation does not use compression of the cleartext input to
prevent repetitions, or other common security improvements. Use with care.

"""
import pathlib
import json
import logging
import logging.config
import atexit

from rsa.key import new_keys, PrivateKey, PublicKey
from rsa.pkcs1 import (
    encrypt,
    decrypt,
    sign,
    verify,
    find_signature_hash,
    sign_hash,
    compute_hash,
)

__author__ = "Sybren Stuvel, Barry Mead and Yesudeep Mangalapilly"
__date__ = "2023-04-23"
__version__ = "4.10-dev0"


def setup_logger() -> None:
    folder = pathlib.Path("logs")

    if not folder.exists():
        folder.mkdir()

    config_file = pathlib.Path(__file__).resolve().parent / "core/config/logger_config.json"

    with open(config_file, "r") as f_in:
        config = json.load(f_in)

    logging.config.dictConfig(config)

    # mypy founds errors, why???
    # queue_handler = logging.getHandlerByName("queue_handler")

    logger = logging.getLogger(__name__)

    queue_handler = None
    for handler in logger.handlers:
        if handler.get_name() == "queue_handler":
            queue_handler = handler
            break

    if queue_handler is not None:
        atexit.register(queue_handler.close)


setup_logger()

# Do doctest if we're run directly
if __name__ == "__main__":
    import doctest

    doctest.testmod()

__all__ = [
    "new_keys",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "PublicKey",
    "PrivateKey",
    "find_signature_hash",
    "compute_hash",
    "sign_hash",
]

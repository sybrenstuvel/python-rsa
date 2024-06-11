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
import atexit
import json
import logging
import logging.config
import logging.handlers
import pathlib
import queue

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

logger = logging.getLogger(__name__)


def setup_logger() -> None:
    project_root = next(
        p for p in pathlib.Path(__file__).parents if p.parts[-1] == 'python-rsa'
    )

    log_folder = project_root / "logs"
    log_folder.mkdir(exist_ok=True)

    with open(project_root / "rsa/core/config/logger_config.json", "r") as f_in:
        config = json.load(f_in)

    for handler in config.get("handlers", {}).values():
        if "filename" in handler:
            handler["filename"] = str(log_folder / pathlib.Path(handler["filename"]).name)

    logging.config.dictConfig(config)

    log_queue = queue.Queue(config["queue_handler"]["queue_size"])

    queue_handler = logging.handlers.QueueHandler(log_queue)
    logger.addHandler(queue_handler)

    file_handler = config["handlers"]["file"]
    stderr_handler = config["handlers"]["stderr"]

    listener = logging.handlers.QueueListener(log_queue, file_handler, stderr_handler)
    listener.start()

    def cleanup():
        try:
            listener.stop()
        except Exception as e:
            logger.error("Error stopping QueueListener: %s", e)
        finally:
            queue_handler.close()
            for handler in logger.handlers:
                handler.close()

    atexit.register(cleanup)

    logger.debug("logger is configured")


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

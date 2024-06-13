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


def __setup_logging():
    """
    On production stop logging, change logger mode to INFO
    """
    project_root = next(
        p for p in pathlib.Path(__file__).parents if p.parts[-1] == 'python-rsa'
    )

    log_folder = project_root / "logs"
    log_folder.mkdir(exist_ok=True)

    with open(project_root / "rsa/core/config/logger_config.json", "r") as f_in:
        config = json.load(f_in)

    for handler_name, handler in config.get("handlers", {}).items():
        if "filename" in handler:
            handler["filename"] = str(log_folder / pathlib.Path(handler["filename"]).name)

    # Set up logging configuration
    logging.config.dictConfig(config)

    log_queue = queue.Queue(-1)
    queue_handler = logging.handlers.QueueHandler(log_queue)

    # Add QueueHandler to root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(queue_handler)

    # Set up QueueListener with existing handlers, excluding QueueHandler
    handlers = [h for h in root_logger.handlers if not isinstance(h, logging.handlers.QueueHandler)]
    listener = logging.handlers.QueueListener(log_queue, *handlers, respect_handler_level=True)
    listener.start()

    def cleanup():
        try:
            listener.stop()
        except Exception as e:
            root_logger.error("Error stopping QueueListener: %s", e)
        finally:
            queue_handler.close()
            for handler in root_logger.handlers:
                handler.close()

    atexit.register(cleanup)

    root_logger.debug("logger is configured")


__setup_logging()

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

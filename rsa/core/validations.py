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


def assert_int(var: int, name: str) -> None:
    if isinstance(var, int):
        return

    raise TypeError("{} should be an integer, not {}".format(name, var.__class__))

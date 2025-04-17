# Python-RSA has been archived

Hi folks,

I'm Sybren, one of the original authors and the maintainer of this project.
Unfortunately I don't have the time and brain space left to properly maintain
Python-RSA. As you can see from the lack of activity on the open issues, and the
lack of commits, that has been the case for a while now.

As Python-RSA is included as a dependency in quite a few high-profile projects,
I don't feel comfortable handing over the project to someone else. It's just too
big of a risk.

Thanks for having used this little library for so long, and in so many projects.
I truely didn't expect that when I started working on it. Also big thanks to all
the people helping out and improving the project.

There are improvements that haven't made it into a new release. As I said, I
don't have the time and the brain space to really investigate and oversee the
security impact of all those changes. It's not a decision I've made lightly.

So that's it. If you want to keep the project alive, please fork it. Give it the
love it deserves, investigate those yet-unreleased improvements, and have a
project that's then already better than how I left this one.

Cheers,
Sybren


---------------------------------------------

# Pure Python RSA implementation

[![RSA Downloads Last Month](https://assets.piptrends.com/get-last-month-downloads-badge/rsa.svg 'RSA Downloads Last Month by pip Trends')](https://piptrends.com/package/rsa)
[![PyPI](https://img.shields.io/pypi/v/rsa.svg)](https://pypi.org/project/rsa/)
[![Build Status](https://travis-ci.org/sybrenstuvel/python-rsa.svg?branch=master)](https://travis-ci.org/sybrenstuvel/python-rsa)
[![Coverage Status](https://coveralls.io/repos/github/sybrenstuvel/python-rsa/badge.svg?branch=master)](https://coveralls.io/github/sybrenstuvel/python-rsa?branch=master)
[![Code Climate](https://api.codeclimate.com/v1/badges/a99a88d28ad37a79dbf6/maintainability)](https://codeclimate.com/github/codeclimate/codeclimate/maintainability)

.. image:: https://assets.piptrends.com/get-last-month-downloads-badge/rsa.svg :alt: rsa Downloads Last Month by pip Trends :target: https://piptrends.com/package/rsa

[Python-RSA](https://stuvel.eu/rsa) is a pure-Python RSA implementation. It supports
encryption and decryption, signing and verifying signatures, and key
generation according to PKCS#1 version 1.5. It can be used as a Python
library as well as on the commandline. The code was mostly written by
Sybren A.  Stüvel.

Documentation can be found at the [Python-RSA homepage](https://stuvel.eu/rsa). For all changes, check [the changelog](https://github.com/sybrenstuvel/python-rsa/blob/master/CHANGELOG.md).

Download and install using:

    pip install rsa

or download it from the [Python Package Index](https://pypi.org/project/rsa/).

The source code is maintained at [GitHub](https://github.com/sybrenstuvel/python-rsa/) and is
licensed under the [Apache License, version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

## Security

Because of how Python internally stores numbers, it is not possible to make a pure-Python program secure against timing attacks. This library is no exception, so use it with care. See https://github.com/sybrenstuvel/python-rsa/issues/230 and https://securitypitfalls.wordpress.com/2018/08/03/constant-time-compare-in-python/ for more info.

For instructions on how to best report security issues, see our [Security Policy](https://github.com/sybrenstuvel/python-rsa/blob/main/SECURITY.md).

## Setup of Development Environment

```
python3 -m venv .venv
. ./.venv/bin/activate
pip install poetry
poetry install
```

## Publishing a New Release

Since this project is considered critical on the Python Package Index,
two-factor authentication is required. For uploading packages to PyPi, an API
key is required; username+password will not work.

First, generate an API token at https://pypi.org/manage/account/token/. Then,
use this token when publishing instead of your username and password.

As username, use `__token__`.
As password, use the token itself, including the `pypi-` prefix.

See https://pypi.org/help/#apitoken for help using API tokens to publish. This
is what I have in `~/.pypirc`:

```
[distutils]
index-servers =
    rsa

# Use `twine upload -r rsa` to upload with this token.
[rsa]
  repository = https://upload.pypi.org/legacy/
  username = __token__
  password = pypi-token
```

```
. ./.venv/bin/activate

poetry build
twine check dist/rsa-4.10-dev0.tar.gz dist/rsa-4.10-dev0-*.whl
twine upload -r rsa dist/rsa-4.10-dev0.tar.gz dist/rsa-4.10-dev0-*.whl
```

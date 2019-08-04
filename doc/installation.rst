Installation
============

Installation can be done in various ways. The simplest form uses pip::

    pip install rsa

Depending on your system you may need to use ``sudo pip`` if you want to install
the library system-wide, or use ``pip install --user rsa`` to install the
library in your home directory.

The sources are tracked in our `Git repository`_ at
GitHub. It also hosts the `issue tracker`_.

.. _`Git repository`: https://github.com/sybrenstuvel/python-rsa.git
.. _`issue tracker`: https://github.com/sybrenstuvel/python-rsa/issues


Dependencies
------------

Python-RSA is compatible with Python versions 3.5 and newer. The last
version with Python 2.7 support was Python-RSA 4.0.

Python-RSA has very few dependencies. As a matter of fact, to use it
you only need Python itself. Loading and saving keys does require an
extra module, though: pyasn1. If you used pip or easy_install like
described above, you should be ready to go.


Development dependencies
------------------------

In order to start developing on Python-RSA, use Git_ to get a copy of
the source::

    git clone https://github.com/sybrenstuvel/python-rsa.git

Use Poetry_ to install the development requirements in a virtual environment::

    cd python-rsa
    poetry install

.. _Git: https://git-scm.com/
.. _Poetry: https://poetry.eustace.io/

Cryptography-gocrypto
=====================

.. image:: https://travis-ci.org/cyli/cryptography-gocrypto.svg?branch=master
    :target: https://travis-ci.org/cyli/cryptography-gocrypto

.. image:: https://codecov.io/github/cyli/cryptography-gocrypto/coverage.svg?branch=master
    :target: https://codecov.io/github/cyli/cryptography-gocrypto?branch=master

**At this time this should be considered experimental software and not ready
for any sort of production use.**

This is an experimental backend for using golang crypto with `cryptography`_.
And when we say experimental we mean "do not touch this with a ten foot pole
right now".

Usage
-----

Then, if all is well you can import the backend and use hashing
from `cryptography`_.

.. code-block:: pycon

    >>> from cryptography_gocrypto.backend import backend


Supported Interfaces
--------------------

* HashBackend (except copy)

Issues
------

* No one should use this yet.

.. _`cryptography`: https://cryptography.io/

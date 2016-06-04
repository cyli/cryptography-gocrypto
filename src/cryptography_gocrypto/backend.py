# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.hazmat.backends.interfaces import (
    HMACBackend, HashBackend
)

from cryptography_gocrypto.binding import Binding
from cryptography_gocrypto.hashes import _HashContext
from cryptography_gocrypto.hmac import _HMACContext


@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
class Backend(object):
    """
    GoCrypto API wrapper.
    """
    name = "gocrypto"

    def __init__(self):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib

    def hash_supported(self, algorithm):
        result = self._lib.CreateHash(algorithm.name)
        if result:
            self._lib.DownRef(result)
            return True
        else:
            return False

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)

    def hmac_supported(self, algorithm):
        return self.hash_supported(algorithm)

    def create_hmac_ctx(self, key, algorithm):
        return _HMACContext(self, algorithm, key)


backend = Backend()
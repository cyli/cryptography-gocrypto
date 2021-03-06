# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HMACBackend, HashBackend
)

from cryptography_gocrypto.binding import Binding
from cryptography_gocrypto.hashes import _HashContext
from cryptography_gocrypto.hmac import _HMACContext
from cryptography_gocrypto.ciphers import _CipherContext, is_cipher_supported


@utils.register_interface(CipherBackend)
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
        return self._lib.IsHashSupported(algorithm.name) == 1

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)

    def hmac_supported(self, algorithm):
        return self.hash_supported(algorithm)

    def create_hmac_ctx(self, key, algorithm):
        return _HMACContext(self, algorithm, key)

    def cipher_supported(self, cipher, mode):
        return is_cipher_supported(self, cipher, mode)

    def create_symmetric_encryption_ctx(self, cipher, mode):
        # 0 for decryption, 1 for encryption
        return _CipherContext(self, cipher, mode, 1)

    def create_symmetric_decryption_ctx(self, cipher, mode):
        # 0 for decryption, 1 for encryption
        return _CipherContext(self, cipher, mode, 0)


backend = Backend()

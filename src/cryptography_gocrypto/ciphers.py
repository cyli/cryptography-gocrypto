# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import modes


@utils.register_interface(ciphers.CipherContext)
class _CipherContext(object):
    def __init__(self, backend, cipher, mode, operation):
        self._backend = backend
        self._cipher = cipher
        self._mode = mode
        self._operation = operation

        # iv is only for cbc
        ctx = self._backend._lib.CreateCipher(
            cipher.name, mode.name, operation,
            mode.initialization_vector, len(mode.initialization_vector),
            cipher.key, len(cipher.key))

        if ctx == 0:
            raise Exception("who knows")

        self._ctx = ctx
        self._buffer = []

    def update(self, data):
        self._buffer += data
        block_size = self._cipher.block_size // 8
        to_update = self._buffer[
            :(len(self._buffer) // block_size) * block_size]
        if to_update:
            dst = self._backend._ffi.new("char []", len(to_update))
            self._backend._lib.UpdateCipher(
                self._ctx, dst, to_update, len(to_update))
            self._buffer = self._buffer[len(to_update):]
            return self._backend._ffi.buffer(dst, len(to_update))[:]
        return b""

    def finalize(self):
        if self._buffer:
             raise ValueError("The length of the provided data is not a "
                              "multiple of the block length.")
        return b""

# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import BlockCipherAlgorithm, modes


def is_cipher_supported(backend, cipher, mode):
    """
    Is the cipher and mode supported?
    """
    return (isinstance(cipher, BlockCipherAlgorithm) and
            isinstance(mode, modes.Mode) and
            backend._lib.IsCipherSupported(
                cipher.name.lower(), mode.name.lower()) == 1)

@utils.register_interface(ciphers.CipherContext)
class _CipherContext(object):
    def __init__(self, backend, cipher, mode, operation):
        self._backend = backend
        self._cipher = cipher
        self._mode = mode
        self._operation = operation

        if not is_cipher_supported(backend, cipher, mode):
            raise UnsupportedAlgorithm(
                "cipher {0} in mode {1} is not supported by this backend"
                .format(cipher.name if cipher else cipher,
                        mode.name if mode else mode),
                _Reasons.UNSUPPORTED_CIPHER
            )

        iv_or_nonce = ""
        if isinstance(mode, modes.ModeWithInitializationVector):
            iv_or_nonce = mode.initialization_vector
        elif isinstance(mode, modes.ModeWithNonce):
            iv_or_nonce = mode.nonce

        print("python", cipher.key_sizes)
        ctx = self._backend._lib.CreateCipher(
            cipher.name.lower(), mode.name.lower(), operation,
            iv_or_nonce, len(iv_or_nonce),
            cipher.key, len(cipher.key))

        if ctx == -1:
            raise ValueError(
                "cipher {0} in {1} mode errored with the provided parameters."
                .format(cipher.name, mode.name)
            )

        self._ctx = ctx
        self._buffer = []

    def update(self, data):
        self._buffer += data
        block_size = self._cipher.block_size // 8
        to_update = self._buffer[
            :(len(self._buffer) // block_size) * block_size]
        print("block size:", block_size, to_update)
        if to_update:
            dst = self._backend._ffi.new("char []", len(to_update))
            self._backend._lib.UpdateCipher(
                self._ctx, dst, to_update, len(to_update))
            result = self._backend._ffi.buffer(dst, len(to_update))[:]
            self._buffer = self._buffer[len(to_update):]
            return result
        return b""

    def finalize(self):
        if self._buffer:
             raise ValueError("The length of the provided data is not a "
                              "multiple of the block length.")
        return b""

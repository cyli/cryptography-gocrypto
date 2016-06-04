# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import (
    InvalidSignature, UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.primitives import constant_time, hashes, interfaces


@utils.register_interface(interfaces.MACContext)
@utils.register_interface(hashes.HashContext)
class _HMACContext(object):
    def __init__(self, backend, algorithm, key):
        self._algorithm = algorithm
        self._backend = backend

        ctx = self._backend._lib.CreateHMAC(algorithm.name, key, len(key))
        if ctx == 0:
            raise UnsupportedAlgorithm(
                "{0} is not a supported for HMAC on this backend.".format(
                    algorithm.name),
                _Reasons.UNSUPPORTED_HASH
            )
        ctx = self._backend._ffi.new("long long *", ctx)

        ctx = self._backend._ffi.gc(
            ctx, lambda x: backend._lib.DownRef(x[0])
        )

        self._ctx = ctx

    algorithm = utils.read_only_property("_algorithm")

    def copy(self):
        raise NotImplementedError

    def update(self, data):
        self._backend._lib.UpdateHMAC(self._ctx[0], data, len(data))

    def finalize(self):
        buf = self._backend._lib.FinalizeHMAC(self._ctx[0])
        assert buf != self._backend._ffi.NULL
        return self._backend._ffi.buffer(buf, self.algorithm.digest_size)[:]

    def verify(self, signature):
        digest = self.finalize()
        if not constant_time.bytes_eq(digest, signature):
            raise InvalidSignature("Signature did not match digest.")

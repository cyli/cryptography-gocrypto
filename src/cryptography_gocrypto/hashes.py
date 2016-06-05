# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import hashes


@utils.register_interface(hashes.HashContext)
class _HashContext(object):
    def __init__(self, backend, algorithm, ctx=None):
        self._algorithm = algorithm
        self._backend = backend

        if ctx is None:
            ctx = self._backend._lib.CreateHash(algorithm.name)
            if ctx == 0:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend.".format(
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
        return _HashContext(self._backend, self._algorithm,
                            self._backend._lib.CopyHashOrHMAC(self._ctx[0]))

    def update(self, data):
        self._backend._lib.UpdateHashOrHMAC(self._ctx[0], data, len(data))

    def finalize(self):
        buf = self._backend._lib.FinalizeHashOrHMAC(self._ctx[0])
        assert buf != self._backend._ffi.NULL
        return self._backend._ffi.buffer(buf, self.algorithm.digest_size)[:]

# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import cffi


ffi = cffi.FFI()
ffi.cdef("""
typedef long long GoInt64;
typedef GoInt64 GoInt;
GoInt CreateHash(char *);
void UpdateHash(GoInt, char *, GoInt);
char *FinalizeHash(GoInt);
GoInt CreateHMAC(char *, char *, int);
void UpdateHMAC(GoInt, char *, int);
char* FinalizeHMAC(GoInt p0);
void UpRef(GoInt);
void DownRef(GoInt);
""")

curdir = os.path.dirname(os.path.abspath(__file__))
lib = ffi.dlopen(os.path.join(curdir, "gocrypto.so"))


class Binding(object):
    """
    GoCrypto API wrapper.
    """
    lib = lib
    ffi = ffi

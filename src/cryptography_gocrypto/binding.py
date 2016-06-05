# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import cffi


ffi = cffi.FFI()
ffi.cdef("""
int IsHashSupported(char *);
long long CreateHash(char *);
int UpdateHashOrHMAC(long long, char *, int);
char * FinalizeHashOrHMAC(long long);
long long CopyHashOrHMAC(long long);
long long CreateHMAC(char *, char *, int);
long long CreateCipher(char *, char *, int, char *, int, char *, int);
int UpdateCipher(long long, char *, char *, int);

void UpRef(long long);
void DownRef(long long);
""")

curdir = os.path.dirname(os.path.abspath(__file__))
lib = ffi.dlopen(os.path.join(curdir, "gocrypto.so"))


class Binding(object):
    """
    GoCrypto API wrapper.
    """
    lib = lib
    ffi = ffi

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# The MIT License (MIT)
#
# Copyright (c) 2016 Matthew Pare (paretech@gmail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
from io import BytesIO
from io import IOBase
from klvdata.common import bytes_to_int, ber_decode, hexstr_to_bytes

LV_KEY_HEADER = hexstr_to_bytes('06 0E 2B 34')
LV_KEY_V1 = hexstr_to_bytes('06 0E 2B 34 - 01 01 01 01 - 0F 00 00 00 - 00 00 00 00')
LV_KEY_V2 = hexstr_to_bytes('06 0E 2B 34 - 02 0B 01 01 – 0E 01 03 01 - 01 00 00 00')

class KLVParser(object):
    """Return key, value pairs parsed from an SMPTE ST 336 source."""
    def __init__(self, source, key_length):
        if isinstance(source, IOBase):
            self.source = source
        else:
            self.source = BytesIO(source)

        self.key_length = key_length

    def __iter__(self):
        return self

    def __next__(self):
        key = self.__align_to_key()

        byte_length = bytes_to_int(self.__read(1))

        if byte_length < 128:
            # BER Short Form
            length = byte_length
        else:
            # BER Long Form
            length = bytes_to_int(self.__read(byte_length - 128))

        value = self.__read(length)

        return key, value

    def __align_to_key(self):
        b = bytearray(self.key_length)
        n = self.source.readinto(b)
        if n == 0 or n < len(b):
            raise StopIteration
        while True:
            idx = b.find(LV_KEY_HEADER)
            if idx == 0:
                return bytes(b)

            if idx == -1:
                # not found but could be across boundaries
                # expand the buffer. keep the last 3 bytes of the buffer
                len_keep_buffer = 4-1
                b[-len_keep_buffer:] += self.__read(16 - 3)
                continue
            # if idx != 0 && idx != -1
            # we need to read more data
            available = n-idx
            missing = 16 - available
            bb = bytearray(missing)
            nn = self.source.readinto(bb)
            if nn != missing:
                # Data stream terminated
                raise StopIteration
            key = b[idx:] + b[:nn]
            return bytes(key)

    def __read(self, size):
        if size == 0:
            return b''

        assert size > 0, size
        assert size < sys.maxsize, size

        data = self.source.read(size)

        if data:
            return data
        else:
            raise StopIteration

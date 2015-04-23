# Copyright (c) 2011-2015 Spotify AB
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# A standalone implementation of RSA signature generation and verification
# as used in SSH with SHA-1 as hash algorithm, specified in RFC3447 section
# 8.2.

import base64
import hashlib
import binascii

from crtauth import exceptions
from crtauth.constant_time_compare import constant_time_compare


class RSAPrivateKey(object):
    def __init__(self, private_key):
        """private_key is expected to be in PEM format as described in
        RFC3447 A.1.2. This is what ssh-keygen outputs in the id_rsa output
        file"""
        private_key = private_key.strip()
        decoded = base64.b64decode("".join(private_key.split("\n")[1:-1]))

        items = _read_items(decoded)

        self.private_exp = items[3]
        self.mod = items[1]
        # it turns out that ssh writes leading zeroes, which we get rid of
        # by doing a round trip to a (very long) int.
        self.mod_size = len(_int_to_str(self.mod))
        self.padding = _make_padding(self.mod_size)

    def encrypt(self, data):
        if len(data) > self.mod_size:
            raise exceptions.KeyError("Key size too small, more than %d bytes "
                                      "of data can not be encrypted" %
                                      self.mod_size)
        return _int_to_str(pow(_str_to_int(data), self.private_exp, self.mod))

    def sign(self, data):
        digest = hashlib.sha1(data).digest()
        return self.encrypt(self.padding + digest)


class RSAPublicKey(object):
    """Instances of this class represents a public RSA key"""

    def __init__(self, key):
        """@param key the ASCII string from id_rsa.pub from ssh-keygen"""
        if key.startswith("ssh-rsa"):
            self.decoded = key.split(" ")[1]
            self.encoded = base64.b64decode(self.decoded)
        else:
            self.encoded = key
            self.decoded = base64.b64encode(self.encoded)

        self.fp = hashlib.sha1(self.encoded).digest()[:6]

        fields = read_fields(self.encoded)
        sigtype = fields.next()
        if sigtype != "ssh-rsa":
            raise exceptions.KeyError("Unknown key type %s. This code "
                                      "currently only supports ssh-rsa" %
                                      sigtype)
        self.exp = _str_to_int(fields.next())
        self.mod = _str_to_int(fields.next())
        # it turns out that ssh writes leading zeroes, which we get rid of
        # by roundtripping to bignum.
        self.mod_size = len(_int_to_str(self.mod))

    def __repr__(self):
        return self.encoded

    def __len__(self):
        return len(self.encoded)

    def fingerprint(self):
        return self.fp

    def decrypt(self, cleartext):
        n = _str_to_int(cleartext)
        return _int_to_str(pow(n, self.exp, self.mod))

    def verify_signature(self, signature, data):
        # for some reason, highest byte in padding is 0 that disappears in
        # the encryption roundtrip, so we need to add zeroes to be able to
        # compare.
        decrypted = self.decrypt(signature)
        if len(decrypted) < self.mod_size:
            decrypted = ("\x00" *
                         (self.mod_size - len(decrypted))) + decrypted
        padded_digest = (_make_padding(self.mod_size) +
                         hashlib.sha1(data).digest())
        return constant_time_compare(padded_digest, decrypted)


def read_fields(bytes):
    off = 0
    while off < len(bytes):
        l = s2i(bytes[off:])
        off += 4
        yield bytes[off:off + l]
        off += l


def s2i(data):
    """Read four bytes off the provided byte string and return the value as
    a big endian 32 bit unsigned integer"""
    num = 0
    for i, val in enumerate(data[:4]):
        num += ord(val) << ((3 - i) * 8)
    return num


def _make_padding(mod_length):
    """
    Creates a padding string that when concatenated with the SHA-1 checksum
    results in a EMSA-PKCS1-v1_5 encoded string as specified in RFC3447
    section 9.2
    """

    # Constant for SHA-1 taken from RFC3447 page 42 note 1
    PS = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
    all_ff = "\xff" * (mod_length - len(PS) - 23)
    return "\x00\x01" + all_ff + "\x00" + PS


def _read_items(data):
    """
    Very simplistic ASN.1 parser, assuming the top level is a COLLECTION and
    the contents of that some primitive types.
    """
    offset = 0

    items = []
    while len(data) > offset:
        type = ord(data[offset])
        offset += 1
        length = 0
        if ord(data[offset]) & 0x80:
            len_octets = ord(data[offset]) ^ 0x80
            offset += 1
            for i in range(len_octets):
                length += ord(data[offset + i]) << (len_octets - i - 1) * 8
            offset += len_octets
        else:
            length = ord(data[offset])
            offset += 1
        if type == 0x30:
            return _read_items(data[offset:offset + length])
        elif type == 0x02:
            items.append(_str_to_int(data[offset:offset + length]))

        offset += length

    return items


def _str_to_int(data):
    """Treats the provided string as a sequence of octets and interprets
    the octets as an arbitrarily sized unsigned integer in network byte
    order
    """
    return int(data.encode('hex'), 16)


def _int_to_str(num):
    """Packs the num (which must be convertible to a long) into a
       byte string. The resulting byte string is the big-endian two's
       complement representation of the passed in long."""
    s = hex(num)[2:]
    s = s.rstrip('L')
    if len(s) & 1:
        s = '0' + s
    s = binascii.unhexlify(s)
    return s

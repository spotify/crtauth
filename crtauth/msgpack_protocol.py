# Copyright (c) 2014 Spotify AB
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
import hashlib
import hmac
import io

import msgpack

from crtauth import exceptions
from crtauth.constant_time_compare import constant_time_compare


PROTOCOL_VERSION = 1
HMAC_HASH_ALGORITHM = hashlib.sha256

HMAC_SIZE = HMAC_HASH_ALGORITHM().digest_size


class TypeInfo(object):
    """
    TypeInfo instances contains extra information about the type of a field
    """
    def __init__(self, data_type, size=None, binary=False):
        self._data_type = data_type
        self._size = size
        self._packer = msgpack.Packer(use_bin_type=binary)

    def validate(self, data, name):
        if not isinstance(data, self._data_type):
            raise ValueError("Value for field %s should have been of %s"
                             % (name, self._data_type))

    def pack(self, value, stream):
        stream.write(self._packer.pack(value))


class MessageBase(object):
    """
    Base class with common functionality for Message and AuthenticatedMessage
    """
    __fields__ = None
    __magic__ = None

    def __init__(self, **kw):
        if len(kw) != len(self.__fields__):
            raise RuntimeError("Wrong number of constructor parameters, "
                               "expected %d got %d",
                               len(self.__fields__), len(kw))

        for key, _ in self.__fields__:
            val = kw.get(key, None)
            if val is None:
                raise RuntimeError(
                    "Missing required argument '%s'" % key)
            setattr(self, key, val)

    def _do_serialize(self):
        if self.__magic__ is None or self.__fields__ is None:
            raise RuntimeError(
                "Serialization can only be performed on classes implementing "
                "__fields__ and __magic__")
        buf = io.BytesIO()
        msgpack.pack(PROTOCOL_VERSION, buf)
        msgpack.pack(self.__magic__, buf)
        for name, type_info in self.__fields__:
            value = getattr(self, name)
            type_info.validate(value, name)
            type_info.pack(value, buf)
        return buf

    @classmethod
    def _do_deserialize(cls, serialized):
        stream = io.BytesIO(serialized)
        unpacker = msgpack.Unpacker(stream)
        version = unpacker.unpack()
        if version != PROTOCOL_VERSION:
            raise exceptions.ProtocolError(
                "Wrong version, expected %d got %d" % (PROTOCOL_VERSION,
                                                       version))
        magic = unpacker.unpack()
        if magic != cls.__magic__:
            raise exceptions.ProtocolError(
                "Wrong magic, expected %d got %d" % (cls.__magic__, magic))
        kw = dict()
        for name, type_info in cls.__fields__:
            kw[name] = unpacker.unpack()
        return cls(**kw), unpacker

    @classmethod
    def deserialize(cls, serialized):
        return cls._do_deserialize(serialized)[0]


class Message(MessageBase):
    """
    Base class for messages not authenticated with a HMAC code
    """
    def serialize(self):
        return self._do_serialize().getvalue()


class AuthenticatedMessage(MessageBase):
    """
    Base class for messages authenticated with a HMAC code
    """
    def serialize(self, hmac_secret):
        """
        Serialises this instance into the serialization format and appends
        a SHA256 HMAC at the end computed using the provided hmac_secret
        """
        buf = self._do_serialize()
        offset = buf.tell()
        buf.seek(0)
        mac = hmac.new(hmac_secret, buf.read(), HMAC_HASH_ALGORITHM)
        buf.seek(offset)
        buf.write(msgpack.Packer(use_bin_type=True).pack(mac.digest()))
        return buf.getvalue()

    @classmethod
    def deserialize_authenticated(cls, serialized, hmac_secret):
        """
        Deserialises instances of this class, validating the HMAC appended
        at the end using the provided hmac_secret
        """
        instance, unpacker = cls._do_deserialize(serialized)
        # the extra 2 bytes taken off is the serialization overhead of byte
        # strings shorter than 256 bytes.
        calculated_mac = hmac.new(hmac_secret, serialized[:-HMAC_SIZE-2],
                                  HMAC_HASH_ALGORITHM).digest()
        stored_mac = unpacker.unpack()
        if not constant_time_compare(calculated_mac, stored_mac):
            # TODO better exception, perhaps?
            raise exceptions.BadResponse("Invalid authentication code")
        return instance


class Challenge(AuthenticatedMessage):
    """
    A challenge.
    """
    __magic__ = ord('c')
    __fields__ = (
        ("unique_data", TypeInfo(str, 20, binary=True)),
        ("valid_from", TypeInfo(int)),
        ("valid_to", TypeInfo(int)),
        ("fingerprint", TypeInfo(str, 6, binary=True)),
        ("server_name", TypeInfo(str)),
        ("username", TypeInfo(str))
    )


class Response(Message):
    """
    A response (a copy of the challenge plus a signature)
    """
    __magic__ = ord('r')
    __fields__ = (
        ("challenge", TypeInfo(str, binary=True)),
        ("signature", TypeInfo(str, binary=True)),
    )


class Token(AuthenticatedMessage):
    """
    Represents a token used to authenticate the user
    """
    __magic__ = ord("t")
    __fields__ = (
        ("valid_from", TypeInfo(int)),
        ("valid_to", TypeInfo(int)),
        ("username", TypeInfo(str))
    )

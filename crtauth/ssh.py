# Copyright (c) 2011-2013 Spotify AB
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

import base64
import sys
import os
import socket
import struct

from crtauth import exceptions
from crtauth import rsa

# ssh-agent communication protocol constants
SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENT_IDENTITIES_ANSWER = 12
SSH2_AGENTC_SIGN_REQUEST = 13
SSH2_AGENT_SIGN_RESPONSE = 14


def base64url_decode(s):
    """
    Decodes a url-safe base64 encoded string.
    """

    if type(s) is unicode:
        s = s.encode("US-ASCII")

    if len(s) % 4 == 3:
        s += "="
    elif len(s) % 4 == 2:
        s += "=="

    # b64decode is real crap when checking for the validity of the input.
    try:
        return base64.b64decode(s, "-_")
    except:
        _, e, tb = sys.exc_info()
        raise exceptions.InvalidInputException(
            "Invalid base64 sequence: %s" % e), None, tb


def base64url_encode(data):
    """
    encodes a url-safe base64 encoded string.
    """

    s = base64.b64encode(data, "-_")
    return s.rstrip("=")


def i2s(i):
    return struct.pack("!I", i)


def write_field(socket, data):
    if type(data) is int:
        data = chr(data)
    elif type(data) is not str:
        data = repr(data)
    socket.send(i2s(len(data)) + data)


class SigningPlug(object):
    """
    Base-class for signing a challenge with an RSA-key. This class
    should never be used directly. The actual signing capabilities are
    implemented in it's subclasses.

    Signing classes can also be used as context managers.
    """
    def sign(self, data, fingerprint):
        raise NotImplementedError("Don't use the SigningPlug directly. This "
                                  "is an abstract base class")

    def __enter__(self):
        pass

    def __exit__(self, exc_class, exc_value, bt):
        self.close()

    def close(self):
        pass


class SingleKeySigner(SigningPlug):
    """Simple implementation of SigningPlug, which holds a single private
    key for signing.

    SingleKeySigner is intended for services, cron-jobs and similar that does
    not have an ssh-agent readily available.
    """
    def __init__(self, priv_key):
        self.key = rsa.RSAPrivateKey(priv_key)

    def sign(self, data, fingerprint):
        return self.key.sign(data)


class AgentSigner(SigningPlug):
    """
    An implementation of SigningPlug, which gets it's private key from an
    ssh-agent.

    AgentSigner is intended for command line tools where their invoker
    also controls an ssh-agent process that can be contacted via a UNIX
    referenced by the SSH_AUTH_SOCK environment variable.
    """
    def __init__(self):
        self.sock = socket.socket(socket.AF_UNIX)
        sock_path = os.getenv("SSH_AUTH_SOCK")
        if not sock_path:
            raise exceptions.SshAgentError(
                "The environment variable SSH_AUTH_SOCK is not set. Please "
                "configure your ssh-agent.")
        self.sock.settimeout(5.0)
        self.sock.connect(sock_path)

    def __find_key(self, key_fingerprint):
        write_field(self.sock, SSH2_AGENTC_REQUEST_IDENTITIES)
        length, response_code, count = struct.unpack("!IBI",
                                                     self.sock.recv(9))
        assert response_code == SSH2_AGENT_IDENTITIES_ANSWER
        resp = self.sock.recv(length - 5)
        fields = rsa.read_fields(resp)
        for i in xrange(count):
            try:
                key = rsa.RSAPublicKey(fields.next())
            except exceptions.KeyError:
                fields.next()
                continue
            fields.next()  # ignore filename for key
            if key.fingerprint() == key_fingerprint:
                return key

    def sign(self, data, fingerprint):
        try:
            pub_key = self.__find_key(fingerprint)

            if not pub_key:
                raise exceptions.SshAgentError(
                    "Your ssh-agent does not have the required key added. This "
                    "usually indicates that ssh-add has not been run.")

            self.sock.send(i2s(len(pub_key) + len(data) + 13) +
                           chr(SSH2_AGENTC_SIGN_REQUEST))
            write_field(self.sock, pub_key)
            write_field(self.sock, data)
            self.sock.send("\0\0\0\0")
            length, response_code, resp_len = struct.unpack("!IBI",
                                                            self.sock.recv(9))
            assert response_code == SSH2_AGENT_SIGN_RESPONSE
            buf = self.sock.recv(length - 5)
            fields = rsa.read_fields(buf)
            response_type = fields.next()
            assert response_type == "ssh-rsa"
            return fields.next()
        except socket.timeout as why:
            raise exceptions.SshAgentError(why)

    def close(self):
        self.sock.close()

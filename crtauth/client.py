# Copyright (c) 2011-2014 Spotify AB
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
import io
import msgpack
from crtauth import ssh, protocol, msgpack_protocol, exceptions


def create_request(username):
    """
    Create a request for a challenge with your username encoded.
    :param username: the username of the user to authenticate as
    :return: a request message
    """
    buf = io.BytesIO()
    msgpack.pack(1, buf)
    msgpack.pack(ord('q'), buf)
    msgpack.pack(username, buf)
    return ssh.base64url_encode(buf.getvalue())


def create_response(challenge, server_name, signer_plug=None):
    """Called by a client with the challenge provided by the server
    to generate a response using the local ssh-agent"""

    b = ssh.base64url_decode(challenge)

    if b[0] == 'v':
        # this is version 0 challenge
        hmac_challenge = protocol.VerifiablePayload.deserialize(b)
        challenge = protocol.Challenge.deserialize(hmac_challenge.payload)
        to_sign = hmac_challenge.payload
        version_1 = False
    elif b[0] == '\x01':
        # version 1
        challenge = msgpack_protocol.Challenge.deserialize(b)
        to_sign = b
        version_1 = True
    else:
        raise exceptions.ProtocolError("invalid first byte of challenge")

    if challenge.server_name != server_name:
        s = ("Possible MITM attack. Challenge originates from '%s' "
             "and not '%s'" % (challenge.server_name, server_name))
        raise exceptions.InvalidInputException(s)

    if not signer_plug:
        signer_plug = ssh.AgentSigner()

    signature = signer_plug.sign(to_sign, challenge.fingerprint)

    signer_plug.close()

    if version_1:
        response = msgpack_protocol.Response(challenge=b, signature=signature)
    else:
        response = protocol.Response(
            signature=signature, hmac_challenge=hmac_challenge)

    return ssh.base64url_encode(response.serialize())
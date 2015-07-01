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

import unittest
import time
import six

from crtauth import server
from crtauth import key_provider
from crtauth import rsa
from crtauth import protocol
from crtauth import ssh
from crtauth import exceptions
from crtauth import msgpack_protocol
from crtauth.client import create_response
from crtauth.server import create_response as server_create_response

inner_s = (
    "AAAAB3NzaC1yc2EAAAABIwAAAQEArt7xdaxlbzzGlgLhqpLuE5x9d+so0M"
    "JiqQSmiUJojuK+v1cxnYCnQQPF0BkAhw2hiFiDvLLVogIu8m2wCV9XAGxrz38NLHVq"
    "ke+EAduJAfiiD1iwvSLbFBOMVRYfzUoiuPIudwZqmLuCpln1RUE6O/ujmYNyoPS4fq"
    "a1svaiZ4C77tLMi2ztMIX97SN2o0EntrhOonJ1nk+7JLYvkhsT8rX20bg6Mlu909iO"
    "vtTbElnypKzmjFZyBvzZhocRo4yfrekP3s2QyKSIB5ARGenoSoQa43cD93tqbLGK4o"
    "JSkkfxc9HFPo0t+deDorZmelNNFvEn5KeqP0HJvw/jm2U1PQ=="
)

s = six.b("ssh-rsa %s noa@vader.local" % inner_s)

t_pubkey = six.b(
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDK0wNhgGlFZf"
    "BoRBS+M8wGoyOOVunYYjeaoRXKFKfhx288ZIo87WMfN6i5KnUTH3A/mYlVnK4bh"
    "chS6dUFisaXcURvFgY46pUSGuLTZxTe9anIIR/iT+V+8MRDHXffRGOCLEQUl0le"
    "YTht0dc7rxaW42d83yC7uuCISbgWqOANvMkZYqZjaejOOGVpkApxLGG8K8RvNBB"
    "M8TYqE3DQHSyRVU6S9HWLbWF+i8W2h4CLX2Quodf0c1dcqlftClHjdIyed/zQKh"
    "Ao+FDcJrN+2ZDJ0mkYLVlJDZuLk/K/vSOwD3wXhby3cdHCsxnRfy2Ylnt31VF0a"
    "VtlhW4IJ+5mMzmz noa@date.office.spotify.net"
)

test_priv_key = six.b("""-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAytMDYYBpRWXwaEQUvjPMBqMjjlbp2GI3mqEVyhSn4cdvPGSK
PO1jHzeouSp1Ex9wP5mJVZyuG4XIUunVBYrGl3FEbxYGOOqVEhri02cU3vWpyCEf
4k/lfvDEQx1330RjgixEFJdJXmE4bdHXO68WluNnfN8gu7rgiEm4FqjgDbzJGWKm
Y2nozjhlaZAKcSxhvCvEbzQQTPE2KhNw0B0skVVOkvR1i21hfovFtoeAi19kLqHX
9HNXXKpX7QpR43SMnnf80CoQKPhQ3CazftmQydJpGC1ZSQ2bi5Pyv70jsA98F4W8
t3HRwrMZ0X8tmJZ7d9VRdGlbZYVuCCfuZjM5swIDAQABAoIBADtnoHbfQHYGDGrN
ffHTg+9xuslG5YjuA3EzuwkMEbvMSOU8YUzFDqInEDDjoZSvQZYvJw0/LbN79Jds
S2srIU1b7HpIzhu/gVfjLgpTB8bh1w95vDfxxLrwU9uAdwqaojaPNoV9ZgzRltB7
hHnDp28cPcRSKekyK+9fAB8K6Uy8N00hojBDwtwXM8C4PpQKod38Vd0Adp9dEdX6
Ro9suYb+d+qFalYbKIbjKWkll+ZiiGJjF1HSQCTwlzS2haPXUlbk57HnN+8ar+a3
ITTc2gbNuTqBRD1V/gCaD9F0npVI3mQ34eUADNVVGS0xw0pN4j++Da8KXP+pyn/G
DU/n8SECgYEA/KN4BTrg/LB7cGrzkMQmW26NA++htjiWHK3WTsQBKBDFyReJBn67
o9kMTHBP35352RfuJ3xEEJ0/ddqGEY/SzNk3HMTlxBbR5Xq8ye102dxfEO3eijJ/
F4VRSf9sFgdRoLvE62qLudytK4Ku9nnKoIqrMxFweTpwxzf2jjIKDbECgYEAzYXe
QxT1A/bfs5Qd6xoCVOAb4T/ALqFo95iJu4EtFt7nvt7avqL+Vsdxu5uBkTeEUHzh
1q47LFoFdGm+MesIIiPSSrbfZJ6ht9kw8EbF8Py85X4LBXey67JlzzUq+ewFEP91
do7uGQAY+BRwXtzzPqaVBVa94YOxdq/AGutrIqMCgYBr+cnQImwKU7tOPse+tbbX
GRa3+fEZmnG97CZOH8OGxjRiT+bGmd/ElX2GJfJdVn10ZZ/pzFii6TI4Qp9OXjPw
TV4as6Sn/EDVXXHWs+BfRKp059VXJ2HeQaKOh9ZAS/x9QANXwn/ZfhGdKQtyWHdb
yiiFeQyjI3EUFD0SZRya4QKBgA1QvQOvmeg12Gx0DjQrLTd+hY/kZ3kd8AUKlvHU
/qzaqD0PhzCOstfAeDflbVGRPTtRu/gCtca71lqidzYYuiAsHfXFP1fvhx64LZmD
nFNurHZZ4jDqfmcS2dHA6hXjGrjtNBkITZjFDtkTyev7eK74b/M2mXrA44CDBnk4
A2rtAoGAMv92fqI+B5taxlZhTLAIaGVFbzoASHTRl3eQJbc4zc38U3Zbiy4deMEH
3QTXq7nxWpE4YwHbgXAeJUGfUpE+nEZGMolj1Q0ueKuSstQg5p1nwhQIxej8EJW+
7siqmOTZDKzieik7KVzaJ/U02Q186smezKIuAOYtT8VCf9UksJ4=
-----END RSA PRIVATE KEY-----""")


class RoundtripTest(unittest.TestCase):

    def test_read_base64_key(self):
        key = rsa.RSAPublicKey(s)
        self.assertEqual(key.fingerprint(), six.b("\xfb\xa1\xeao\xd3y"))
        self.assertEqual(key.decoded, six.b(inner_s))
        self.assertEqual(
            key.encoded[:15],
            six.b("\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01")
        )

    def test_read_binary_key(self):
        key = rsa.RSAPublicKey(ssh.base64url_decode(
            s.split(six.b(" "))[1])
        )
        self.assertEqual(key.fingerprint(), six.b("\xfb\xa1\xeao\xd3y"))
        self.assertEqual(key.decoded, six.b(inner_s))
        self.assertEqual(
            key.encoded[:15],
            six.b("\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01")
        )

    def test_create_challenge(self):
        auth_server = server.AuthServer(six.b("gurka"), DummyKeyProvider(),
                                        six.b("server.name"))
        s = auth_server.create_challenge(six.b("noa"))
        cb = ssh.base64url_decode(s)

        verifiable_payload = protocol.VerifiablePayload.deserialize(cb)

        challenge = protocol.Challenge.deserialize(verifiable_payload.payload)

        self.assertEquals(six.b("\xfb\xa1\xeao\xd3y"), challenge.fingerprint)

    def test_create_challenge_v1(self):
        auth_server = server.AuthServer(six.b("secret"), DummyKeyProvider(),
                                        six.b("server.name"))
        challenge = auth_server.create_challenge(six.b("noa"), 1)
        cb = ssh.base64url_decode(challenge)

        decoded_challenge = msgpack_protocol.Challenge.deserialize(cb)

        self.assertEquals(
            six.b("\xfb\xa1\xeao\xd3y"),
            decoded_challenge.fingerprint
        )

    def test_create_challenge_no_legacy_support(self):
        auth_server = server.AuthServer(six.b("secret"), DummyKeyProvider(),
                                        six.b("server.name"),
                                        lowest_supported_version=1)
        self.assertRaises(exceptions.ProtocolVersionError,
                          auth_server.create_challenge, six.b("noa"))

    def test_create_challenge_v1_another(self):
        auth_server = server.AuthServer(six.b("secret"), DummyKeyProvider(),
                                        six.b("server.name"),
                                        lowest_supported_version=1)
        challenge = auth_server.create_challenge(six.b("noa"), 1)
        cb = ssh.base64url_decode(challenge)

        decoded_challenge = msgpack_protocol.Challenge.deserialize(cb)

        self.assertEquals(
            six.b("\xfb\xa1\xeao\xd3y"),
            decoded_challenge.fingerprint
        )

    def test_authentication_roundtrip(self):
        auth_server = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name"),
        )
        challenge = auth_server.create_challenge(six.b("test"))
        response = create_response(
            challenge,
            six.b("server.name"),
            ssh.SingleKeySigner(test_priv_key)
        )
        token = auth_server.create_token(response)
        self.assertTrue(auth_server.validate_token(token))

    def test_authentication_roundtrip_v1(self):
        auth_server = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name")
        )
        challenge = auth_server.create_challenge(six.b("test"), 1)
        response = create_response(
            challenge,
            six.b("server.name"),
            ssh.SingleKeySigner(test_priv_key)
        )
        token = auth_server.create_token(response)
        self.assertTrue(auth_server.validate_token(token))

    def test_authentication_roundtrip_mitm1(self):
        auth_server = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name")
        )
        challenge = auth_server.create_challenge(six.b("test"))
        try:
            create_response(
                challenge,
                six.b("another.server"),
                ssh.SingleKeySigner(test_priv_key)
            )
            self.fail("Should have gotten InvalidInputException")
        except exceptions.InvalidInputException:
            pass

    def test_authentication_roundtrip_mitm2(self):
        auth_server_a = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name")
        )
        challenge = auth_server_a.create_challenge(six.b("test"))
        response = create_response(
            challenge,
            six.b("server.name"),
            ssh.SingleKeySigner(test_priv_key)
        )
        auth_server_b = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("another.server")
        )
        try:
            auth_server_b.create_token(response)
            self.fail("should have thrown exception")
        except exceptions.InvalidInputException:
            pass

    def test_create_token_too_new(self):
        auth_server_a = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name")
        )
        challenge = auth_server_a.create_challenge(six.b("test"))
        response = create_response(
            challenge,
            six.b("server.name"),
            ssh.SingleKeySigner(test_priv_key)
        )
        auth_server_b = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name"),
            now_func=lambda: time.time() - 1000,
        )
        try:
            auth_server_b.create_token(response)
            self.fail("Should have issued InvalidInputException, "
                      "challenge too new")
        except exceptions.InvalidInputException:
            pass

    def test_create_token_invalid_duration(self):
        auth_server = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name")
        )
        token = auth_server._make_token(
            six.b("some_user"),
            int(time.time()) + 3600,
        )

        self.assertRaises(
            exceptions.InvalidInputException,
            auth_server.validate_token,
            token
        )

    def test_create_token_too_old(self):
        auth_server_a = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name")
        )
        challenge = auth_server_a.create_challenge(
            six.b("test")
        )
        response = create_response(
            challenge,
            six.b("server.name"),
            ssh.SingleKeySigner(test_priv_key)
        )
        auth_server_b = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name"),
            now_func=lambda: time.time() + 1000,
        )

        try:
            auth_server_b.create_token(response)
            self.fail("Should have issued InvalidInputException, "
                      "challenge too old")
        except exceptions.InvalidInputException:
            pass

    def test_create_token_invalid_input(self):
        auth_server = server.AuthServer(
            six.b("gurka"), DummyKeyProvider(),
                                        six.b("server.name"))
        data = (
            six.b("2tYneWsOm88qu_Trzahw2r6ZLg37oepv03mykGS-HdcnWJLuUMDOmfVI"),
            six.b("Wl5n3U6qt6Fub2E"),
            six.b("random"),
        )
        for t in data:
            try:
                auth_server.create_token(t)
                self.fail("Input is invalid, should have thrown exception")
            except exceptions.ProtocolError:
                pass

    def test_validate_token_too_old(self):
        auth_server_a = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name")
        )
        challenge = auth_server_a.create_challenge(six.b("test"))
        response = create_response(
            challenge,
            six.b("server.name"),
            ssh.SingleKeySigner(test_priv_key)
        )
        token = auth_server_a.create_token(response)
        auth_server_b = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name"),
            now_func=lambda: time.time() + 1000,
        )
        try:
            auth_server_b.validate_token(token)
            self.fail("Should have issued TokenExpiredException, "
                      "token too old")
        except exceptions.TokenExpiredException:
            pass

    def test_validate_token_too_new(self):
        auth_server_a = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name"),
        )
        challenge = auth_server_a.create_challenge(six.b("test"))
        response = create_response(
            challenge,
            six.b("server.name"),
            ssh.SingleKeySigner(test_priv_key)
        )
        token = auth_server_a.create_token(response)
        auth_server_b = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name"),
            now_func=lambda: time.time() - 1000,
        )
        try:
            auth_server_b.validate_token(token)
            self.fail("Should have issued TokenExpiredException, "
                      "token too new")
        except exceptions.TokenExpiredException:
            pass

    def test_validate_token_wrong_secret(self):
        token = six.b(
            "dgAAAJgtmNoqST9RaxayI7UP5-GLviUDAAAAFHQAAABUJYr_VCWLPQAAAAR0ZXN0"
        )
        auth_server = server.AuthServer(
            six.b("server_secret"),
            DummyKeyProvider(),
            six.b("server.name"),
            now_func=lambda: 1411746561.058992,
        )
        auth_server.validate_token(token)

        auth_server = server.AuthServer(
            six.b("wrong_secret"),
            DummyKeyProvider(),
            six.b("server.name"),
            now_func=lambda: 1411746561.058992
        )
        try:
            auth_server.validate_token(token)
            self.fail("Should have gotten InvalidInputException")
        except exceptions.InvalidInputException:
            pass

    def test_b64_roundtrip(self):
        l = [six.b("a"), six.b("ab"), six.b("abc"), six.b("abcd")]
        for i in l:
            self.assertEquals(ssh.base64url_decode(ssh.base64url_encode(i)), i)

    def test_compatibility_create_response(self):
        self.assertEqual(server_create_response, create_response)


class DummyKeyProvider(key_provider.KeyProvider):
    def get_key(self, username):
        if username == six.b('noa'):
            return rsa.RSAPublicKey(s)
        elif username == six.b('test'):
            return rsa.RSAPublicKey(t_pubkey)
        else:
            raise exceptions.CrtAuthError("Unknown username: %s" % username)

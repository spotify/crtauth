# Copyright (c) 2014-2017 Spotify AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from crtauth import msgpack_protocol, exceptions, rsa
import rsa_test


SERIALIZED_CHALLENGE = (
    '\x01c\xc4\x14uXFO\xd2\xdb\x7f\xfe}\x7f\x93\x91 vh\x89G6\x1f\xc2'
    '\xceQ]\x88\xae\xceQ]\x89\xda\xc4\x06L\x9a\x07\x12\xcb\x1e\xb2se'
    'rver.example.com\xa8username\xc4 \xf7-\xe8\xc8\x1b\xf8\xc5G\xe9'
    '<p\xbde\xc1\xe8\x8f\xe75\x861\xed:?SJ\x7f\xe3V\xfb\xfc\x10\xb2'
)

CHALLENGE = msgpack_protocol.Challenge(
    unique_data='uXFO\xd2\xdb\x7f\xfe}\x7f\x93\x91 vh\x89G6\x1f\xc2',
    valid_from=1365084334,
    valid_to=1365084634,
    fingerprint='L\x9a\x07\x12\xcb\x1e',
    server_name='server.example.com',
    username='username'
)

SERIALIZED_RESPONSE = (
    '\x01r\xc4h\x01c\xc4\x14uXFO\xd2\xdb\x7f\xfe}\x7f\x93\x91 vh\x89'
    'G6\x1f\xc2\xceQ]\x88\xae\xceQ]\x89\xda\xc4\x06L\x9a\x07\x12\xcb'
    '\x1e\xb2server.example.com\xa8username\xc4 \xf7-\xe8\xc8\x1b\xf8'
    '\xc5G\xe9<p\xbde\xc1\xe8\x8f\xe75\x861\xed:?SJ\x7f\xe3V\xfb\xfc'
    '\x10\xb2\xc5\x01\x00?)\xaby\x18\xb7\x0c5B\xcf\x9a\xd4t*\x8b\t\xd0'
    '\x8f\xf3\xdaX\xa6z\xc1\'\xea}\xc9`\xa8\x96)\x19r\x85zi\x8e\xf1lJ'
    '\x91\xa5\x8e4}\xc8\x06q)\x97T\xf6A\x0b\x10\x90\xeb\xb6\x16\x02QK'
    '\xb8\x1b;\xd9\x83\x81M\xdf\xa5\x90\x00E{\xff\xad\x9e\xef\xf9\xf2O'
    '\xcb\x97\xe0\x9dK\xa5\nS\xf3r\xcc\x1d\x1bx\xa3\x10\xcb|x\x06\xae,'
    '\xdf\x92q\xb6\xfb%\xd78\xee{ \x8e\xcdF\xd2\xd9\x8f\xb6z\xfa\xbd'
    '\xfd\xc4\x01Pp\x9bm\xbb\xfe>j\x94\xe1\xfa\xafgr\xa4Nd)Aq\xe9\x13J'
    '\xe1XY?]\xd4\xa2\xb8\xda\x1fO\x99J\xdf\xc3\x0f\xa9\xbc\xdfM\xc4'
    '\xb0;D\n\x0f\xe2\tR\x13\xabV\x8f\'1\xca\xdb{\xe8M\x00\x87=\x98'
    '\xcf\xeaW_\xaaqD\x0c\x10\xcc\x15\xa9\x1b\xfb\x1b\x80\xc8\x1f\xbd'
    'd\xd0!+\xc5\xf3\xff\xc7M\xb8\x89\x00\x1f\xe1\xfcQ\xccb\xc1\xa2\xaf'
    'D5j\xcc\xb4\xb7"y\r\xc0\xb6\x8c\xa846\xd6Y!\xd5\x86'
)

SERIALIZED_TOKEN = (
    '\x01t\xceQ]\x88\xae\xceQ]\x89\xda\xa3noa\xc4 )YT\xc9\x99\xdeI\xc4'
    '\xb9\xed|$\xda\xcc\xaf/A\x93B\x15t\x14_\\\x89d\x19b[\x8d\xe2o'
)


class MsgpackTest(unittest.TestCase):
    def test_build_challenge(self):
        self.assertEqual(CHALLENGE.serialize("secret"), SERIALIZED_CHALLENGE)

        another = msgpack_protocol.Challenge.deserialize_authenticated(
            SERIALIZED_CHALLENGE, "secret")
        for field in ("unique_data", "valid_from", "valid_to", "fingerprint",
                      "server_name", "username"):
            self.assertEquals(getattr(another, field),
                              getattr(CHALLENGE, field))

    def test_wrong_type_unique_data(self):
        challenge = msgpack_protocol.Challenge(
            unique_data=42,
            valid_from=1365084334,
            valid_to=1365084634,
            fingerprint='L\x9a\x07\x12\xcb\x1e',
            server_name='server.example.com',
            username='username'
        )
        self.assertRaises(ValueError, challenge.serialize, "secret")

    def test_wrong_number_of_parameters(self):
        self.assertRaises(RuntimeError, msgpack_protocol.Challenge)

    def test_wrong_name_parameters(self):
        self.assertRaises(RuntimeError, msgpack_protocol.Challenge, a=1, b=2,
                          c=3, d=4, e=5, f=6)

    def test_serialize_no__magic__(self):
        class Dummy(msgpack_protocol.Message):
            def __init__(self):
                self.__fields__ = ()
                super(Dummy, self).__init__()
        self.assertRaises(RuntimeError, Dummy().serialize)

    def test_wrong_version(self):
        try:
            msgpack_protocol.Challenge.deserialize("foo")
            self.fail("Should have thrown wrong version exception")
        except exceptions.ProtocolError as e:
            self._starts_with(e.message, "Wrong version")

    def test_wrong_magic(self):
        try:
            msgpack_protocol.Challenge.deserialize("\x01f")
            self.fail("Should have thrown wrong magic exception")
        except exceptions.ProtocolError as e:
            self._starts_with(e.message, "Wrong magic")

    def test_serialize_response(self):
        key = rsa.RSAPrivateKey(rsa_test.private_key)
        signature = key.sign(SERIALIZED_CHALLENGE)
        response = msgpack_protocol.Response(challenge=SERIALIZED_CHALLENGE,
                                             signature=signature)

        self.assertEqual(SERIALIZED_RESPONSE, response.serialize())

    def test_deserialize_response(self):
        r = msgpack_protocol.Response.deserialize(SERIALIZED_RESPONSE)
        public_key = rsa.RSAPublicKey(rsa_test.public_key)
        self.assertTrue(public_key.verify_signature(r.signature, r.challenge))

    def test_serialize_token(self):
        r = msgpack_protocol.Token(valid_from=1365084334, valid_to=1365084634,
                                   username='noa')

        self.assertEquals(SERIALIZED_TOKEN, r.serialize('gurkburk'))

    def test_deserialize_token(self):
        t = msgpack_protocol.Token.deserialize_authenticated(SERIALIZED_TOKEN,
                                                             'gurkburk')
        self.assertEquals("noa", t.username)
        self.assertEquals(1365084334, t.valid_from)
        self.assertEquals(1365084634, t.valid_to)

    def test_deserialize_token_wrong_secret(self):
        self.assertRaises(exceptions.BadResponse,
                          msgpack_protocol.Token.deserialize_authenticated,
                          SERIALIZED_TOKEN, 'wrong')

    def test_deserialize_tampered_message(self):
        # identical with SERIALIZED_TOKEN except o -> 0 in the username field
        t = (
            '\x01t\xceQ]\x88\xae\xceQ]\x89\xda\xa3n0a\xc4 )YT\xc9\x99\xdeI\xc4'
            '\xb9\xed|$\xda\xcc\xaf/A\x93B\x15t\x14_\\\x89d\x19b[\x8d\xe2o'
        )
        self.assertRaises(exceptions.BadResponse,
                          msgpack_protocol.Token.deserialize_authenticated,
                          t, 'gurkburk')




    def _starts_with(self, message, prefix):
        if not message.startswith(prefix):
            self.assertFalse("Expected '%s' to be prefix of '%s"
                             % (prefix, message))

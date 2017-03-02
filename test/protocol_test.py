# Copyright (c) 2011-2017 Spotify AB
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

import xdrlib
from crtauth import protocol


ref_token = protocol.Token(
    valid_from=1365084334, valid_to=1365084634, username="noa")


def test_serialize_token():
    p = xdrlib.Packer()
    p.pack_fstring(1, protocol.Token.__magic__)
    p.pack_uint(ref_token.valid_from)
    p.pack_uint(ref_token.valid_to)
    p.pack_string(ref_token.username)
    buf = p.get_buffer()

    ref_buf = ref_token.serialize()

    assert buf == ref_buf


def test_deserialize_token():
    ref_buf = ref_token.serialize()

    token = protocol.Token.deserialize(ref_buf)

    assert token.username == ref_token.username
    assert token.valid_from == ref_token.valid_from
    assert token.valid_to == ref_token.valid_to


def test_serialize_token_binary():
    token = protocol.Token(valid_from=1365084334, valid_to=1365084634,
                           username="noa")
    buf = protocol.Token.serialize(token)
    assert buf == "t\x00\x00\x00Q]\x88\xaeQ]\x89\xda\x00\x00\x00\x03noa\x00"


def test_deserialize_token():
    buf = "t\x00\x00\x00Q]\x8b\x17Q]\x8bU\x00\x00\x00\x04test"
    token = protocol.Token.deserialize(buf)
    assert token.username == 'test'
    assert token.valid_from == 1365084951


def test_serialize_challenge():
    unique_data = '\x859\x9eHK\xc6\x83=\x0c,\xda\xf7K\x8e\xc3\xea}:$\xf8'
    challenge = protocol.Challenge(unique_data=unique_data,
                                   valid_from=1365084334, valid_to=1367073504,
                                   fingerprint="\t\x02\xc8|\x83[",
                                   server_name="example.com", username="user")
    buf = protocol.Challenge.serialize(challenge)
    res = ('c\x00\x00\x00\x859\x9eHK\xc6\x83=\x0c,\xda\xf7K\x8e\xc3\xea}:$'
           '\xf8Q]\x88\xaeQ{\xe2\xe0\x00\x00\x00\x06\t\x02\xc8|\x83['
           '\x00\x00\x00\x00\x00\x0bexample.com\x00\x00\x00\x00\x04user')
    assert buf == res


def test_serialize_padding():
    for i in xrange(1, 5):
        user = "a" * i
        unique_data = '\x859\x9eHK\xc6\x83=\x0c,\xda\xf7K\x8e\xc3\xea}:$\xf8'
        challenge = protocol.Challenge(unique_data=unique_data,
                                       valid_from=1365084334,
                                       valid_to=1367073504,
                                       fingerprint="\t\x02\xc8|\x83[",
                                       server_name="example.com", username=user)
        assert len(protocol.Challenge.serialize(challenge)) % 4 == 0

def test_serialize_response():
    challenge = ('v\x00\x00\x00O\x85q\x97\x03C\x17\x87\xbc\xb4\xa3\xeb1|\xd7'
                 '\xea\xd5\x83\xd7\x11\x00\x00\x00Dc\x00\x00\x00\x7f\xcd\x84'
                 'A"\xdb\x85\x89I-\xd3^\xe2u\xca\xc2S\xb4\xd8\xa2Q|\x05\x82Q'
                 '|\x05\x98\x00\x00\x00\x06\xdbe\xa2\xd4\xf9\x10\x00\x00\x00'
                 '\x00\x00\x0bserver_name\x00\x00\x00\x00\x04test')
    signature = ('g\xf2\xdbSMpha\n\xdb\xd0W\x08r\x90`F\x97y\x97\x04V\xe0\x87'
                 '\x19L\xabf\x1cW\xf1\xaes_\xad\xc8\xf5v\xc0E=\'R\'9\xd3\xb6'
                 '\x07\xf7\xc6\x0eH\x1bQ\xe3\x821!\xaf\x19\x8fG\xc3\xb9\xf0'
                 '\xfb\xfaW\x1es\xbbqT\xc7+\xd8\x8d\x1c\x03\xbf\xd1\xba\x0c'
                 '\xb5n"\x90\xbdI\x8b\x1d\xbe\x1b\x80\r4\x1f\x15@\x18\xa4\xda'
                 '++Y3^]g\xd2\x90AOR\x90;\xf5k/H\xceo\xe0\xc4\x84\x89\xfbl'
                 '\x02\xecM\xb7\x05\x1a\xa9t\x13?\xc7\xfc<\x90+\x80\x86\xa2'
                 '\xb4\xf3\xbc\x08\x7f\xa1h\x03x\x07\xf6\xc6\xea\xb9j\x8c\xcd'
                 '\x1c\xe4\x8f\xe1pS2\x17\x90\xf5\x87\x18\xce\x92\xe1\xd0\xfa'
                 '\x15Yf\xa6t\x80\x88O\x0f\xca\x06\x90\xcc\xf9\x02\x7fo/\t'
                 '\xb0\xbcR\n\x9e\xd4\xff:vr\xa8\x07\x16\xb5\x02_\xcf\x81'
                 '\xa1\xdf\xee{\xe0\x9a\xed\xabE\xde\xe5\x07\x0e\xda<\xe75'
                 '\x04p\x9b\x18\xee\x89\x14+t\xef\xe5\xee\x194\x8d\'\xe9'
                 '\x0b\xd0PF\xfb')
    hmac_challenge = protocol.VerifiablePayload.deserialize(challenge)
    resp = protocol.Response(hmac_challenge=hmac_challenge, signature=signature)
    s = ('r\x00\x00\x00\x00\x00\x01\x00g\xf2\xdbSMpha\n\xdb\xd0W\x08r\x90`F'
         '\x97y\x97\x04V\xe0\x87\x19L\xabf\x1cW\xf1\xaes_\xad\xc8\xf5v\xc0E='
         '\'R\'9\xd3\xb6\x07\xf7\xc6\x0eH\x1bQ\xe3\x821!\xaf\x19\x8fG\xc3\xb9'
         '\xf0\xfb\xfaW\x1es\xbbqT\xc7+\xd8\x8d\x1c\x03\xbf\xd1\xba\x0c\xb5n"'
         '\x90\xbdI\x8b\x1d\xbe\x1b\x80\r4\x1f\x15@\x18\xa4\xda++Y3^]g\xd2'
         '\x90AOR\x90;\xf5k/H\xceo\xe0\xc4\x84\x89\xfbl\x02\xecM\xb7\x05\x1a'
         '\xa9t\x13?\xc7\xfc<\x90+\x80\x86\xa2\xb4\xf3\xbc\x08\x7f\xa1h\x03x'
         '\x07\xf6\xc6\xea\xb9j\x8c\xcd\x1c\xe4\x8f\xe1pS2\x17\x90\xf5\x87'
         '\x18\xce\x92\xe1\xd0\xfa\x15Yf\xa6t\x80\x88O\x0f\xca\x06\x90\xcc'
         '\xf9\x02\x7fo/\t\xb0\xbcR\n\x9e\xd4\xff:vr\xa8\x07\x16\xb5\x02_\xcf'
         '\x81\xa1\xdf\xee{\xe0\x9a\xed\xabE\xde\xe5\x07\x0e\xda<\xe75\x04p'
         '\x9b\x18\xee\x89\x14+t\xef\xe5\xee\x194\x8d\'\xe9\x0b\xd0PF\xfb'
         '\x00\x00\x00`v\x00\x00\x00O\x85q\x97\x03C\x17\x87\xbc\xb4\xa3\xeb'
         '1|\xd7\xea\xd5\x83\xd7\x11\x00\x00\x00Dc\x00\x00\x00\x7f\xcd\x84'
         'A"\xdb\x85\x89I-\xd3^\xe2u\xca\xc2S\xb4\xd8\xa2Q|\x05\x82Q|\x05'
         '\x98\x00\x00\x00\x06\xdbe\xa2\xd4\xf9\x10\x00\x00\x00\x00\x00\x0b'
         'server_name\x00\x00\x00\x00\x04test')
    assert protocol.Response.serialize(resp) == s


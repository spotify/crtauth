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
from crtauth import wsgi


class WsgiTest(unittest.TestCase):
    def test_parse_request(self):
        # trigger short request
        _check_req_v0("noa")

        # trigger v0 request where len(s) % 4 == 1
        _check_req_v0("stack")

        # trigger first byte is > 0x03
        _check_req_v0("BXGjYWJj")

        # second byte is not 'q'
        _check_req_v0("AXOjYWJj")

        # zero length username
        _check_req_v0("AXOg")

        # third byte is something completely else
        _check_req_v0("AXHcYWJj")

        # string length too long (str 16)
        _check_req_v0("AXHaYWJj")

        # string length longer than available bytes
        _check_req_v0("AXGjYWI")

        # string length longer than available bytes (also longer than 31)
        _check_req_v0("AXHZYWJj")

        # a valid v1 'abc' username
        username, version = wsgi.CrtauthMiddleware.parse_request("AXGjYWJj")
        assert username == "abc"
        assert version == 1

def _check_req_v0(request):
    u, v = wsgi.CrtauthMiddleware.parse_request(request)
    assert u == request
    assert v == 0


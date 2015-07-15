# Copyright (c) 2015 Spotify AB
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
import six
import pytest

from mock import Mock
from mock import patch

if six.PY3:
    from aiohttp import web
    from crtauth import aiohttp
    from crtauth.exceptions import NoSuchUserException


@pytest.fixture
def middle():
    app, handler, auth_server = Mock(), Mock(), Mock()
    mid = aiohttp.CrtauthMiddleware(app, handler, auth_server, False, False)
    return mid


@pytest.fixture
def req():
    return Mock()


@pytest.mark.skipif(not six.PY3, reason="aiohttp requires Python 3")
class TestCall:
    def test_disabled(self, middle, req, event_loop):
        middle.disabled = True
        middle.handle_handshake = Mock()

        ret = event_loop.run_until_complete(middle(req))

        assert ret is middle.handler.return_value
        middle.handler.assert_called_once_with(req)
        assert middle.handle_handshake.call_count == 0

    def test_enabled(self, middle, req, event_loop):
        middle.handle_handshake = Mock()
        ret = event_loop.run_until_complete(middle(req))

        assert ret is middle.handle_handshake.return_value
        middle.handle_handshake.assert_called_once_with(req)
        assert middle.handler.call_count == 0


@pytest.mark.skipif(not six.PY3, reason="aiohttp requires Python 3")
class TestHandleHandshake:
    def test_chap_path(self, middle, req):
        req._path = middle.CHAP_PATH
        middle.handshake_path = Mock()
        ret = middle.handle_handshake(req)

        assert ret is middle.handshake_path.return_value
        middle.handshake_path.assert_called_once_with(req)

    def test_chap_path_with_errors(self, middle, req):
        req._path = middle.CHAP_PATH
        middle.handshake_path = Mock(side_effect=Exception())

        with pytest.raises(web.HTTPForbidden):
            middle.handle_handshake(req)

    def test_other_path(self, middle, req):
        req._path = '/light-up-the-night'
        middle.handshake_path = Mock()
        middle.handle_authorization = Mock()

        ret = middle.handle_handshake(req)

        assert ret is middle.handle_authorization.return_value
        middle.handle_authorization.assert_called_once_with(req)
        assert middle.handshake_path.call_count == 0


@pytest.mark.skipif(not six.PY3, reason="aiohttp requires Python 3")
class TestHandleAuthorization:
    def test_no_username_and_manual_authorization(self, middle, req):
        req.headers = {}  # No AUTHORIZATION_HEADER, so no username

        with pytest.raises(web.HTTPForbidden):
            middle.handle_authorization(req)

    def test_token_validation_error(self, middle, req):
        req.headers = {
            middle.AUTHORIZATION_HEADER: 'chap:hehe'
        }
        middle.auth_server.validate_token.side_effect = Exception()

        with pytest.raises(web.HTTPForbidden):
            middle.handle_authorization(req)

    @pytest.mark.randomize(token=str, min_length=1, ncalls=100)
    def test_valid_token(self, middle, req, token):
        req.headers = {
            middle.AUTHORIZATION_HEADER: 'chap:{}'.format(token)
        }

        ret = middle.handle_authorization(req)

        assert ret is middle.handler.return_value
        middle.handler.assert_called_once_with(req)
        middle.auth_server.validate_token.assert_called_once_with(token)


@pytest.mark.skipif(not six.PY3, reason="aiohttp requires Python 3")
class TestHandshakePath:
    def test_no_chap_header(self, middle, req):
        req.headers = {}

        with pytest.raises(web.HTTPForbidden):
            middle.handshake_path(req)

    def test_unknown_chap_method(self, middle, req):
        req.headers = {
            middle.CHAP_HEADER: 'upallnighttillthesun:token'
        }

        with pytest.raises(web.HTTPForbidden):
            middle.handshake_path(req)

    @pytest.mark.randomize(token=str, min_length=1, ncalls=100)
    def test_valid_request(self, middle, req, token):
        middle.handle_request = Mock()
        req.headers = {
            middle.CHAP_HEADER: 'request:{}'.format(token)
        }

        ret = middle.handshake_path(req)
        assert ret is middle.handle_request.return_value
        middle.handle_request.assert_called_once_with(req, token)

    @pytest.mark.randomize(token=str, min_length=1, ncalls=100)
    def test_valid_response(self, middle, req, token):
        middle.handle_response = Mock()
        req.headers = {
            middle.CHAP_HEADER: 'response:{}'.format(token)
        }

        ret = middle.handshake_path(req)
        assert ret is middle.handle_response.return_value
        middle.handle_response.assert_called_once_with(req, token)


@pytest.mark.skipif(not six.PY3, reason="aiohttp requires Python 3")
class TestHandleRequest:
    @patch('crtauth.aiohttp.parse_request')
    def test_failing_to_create_challenge(self, parse_request, middle, req):
        parse_request.return_value = Mock(), Mock()
        middle.auth_server.create_challenge.side_effect = Exception()

        with pytest.raises(web.HTTPForbidden):
            middle.handle_request(req, 'token')

    @patch('aiohttp.web.Response')
    @patch('crtauth.aiohttp.parse_request')
    def test_passing(self, parse_request, Response, middle, req):
        username, version = Mock(), Mock()
        parse_request.return_value = username, version
        middle.auth_server.create_challenge.return_value = 'output'

        ret = middle.handle_request(req, 'token')

        assert ret is Response.return_value
        Response.assert_called_once_with(
            status=200,
            headers={middle.CHAP_HEADER: "challenge:output"}
        )


@pytest.mark.skipif(not six.PY3, reason="aiohttp requires Python 3")
class TestHandleResponse:
    def test_failing_to_create_token(self, middle, req):
        middle.auth_server.create_token.side_effect = Exception()

        with pytest.raises(web.HTTPForbidden):
            middle.handle_response(req, 'token')

    def test_failing_because_user_doesnt_exist(self, middle, req):
        middle.auth_server.create_token.side_effect = NoSuchUserException()

        with pytest.raises(web.HTTPForbidden):
            middle.handle_response(req, 'token')

    @patch('aiohttp.web.Response')
    def test_passing(self, Response, middle, req):
        middle.auth_server.create_token.return_value = 'output'

        ret = middle.handle_response(req, 'token')

        assert ret is Response.return_value
        Response.assert_called_once_with(
            status=200,
            headers={middle.CHAP_HEADER: "token:output"}
        )

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
import sys
import logging

import asyncio

from aiohttp import web

from crtauth.exceptions import NoSuchUserException
from crtauth.util import parse_request


class CrtauthMiddleware:
    """
    For comments about how this mechanism works, consider the WSGI
    implementation to be the reference.

    """

    CHAP_HEADER = "X-CHAP"
    CHAP_PATH = "/_auth"
    AUTH_ENVIRON = "crtauth.username"
    AUTHORIZATION_HEADER = "AUTHORIZATION"
    AUTHORIZATION_TYPE = "chap"

    def __init__(self, app, handler, auth_server,
                 disabled=False, manual_authorization=False):
        self.app = app
        self.handler = handler
        self.auth_server = auth_server
        self.disabled = disabled
        self.manual_authorization = manual_authorization

        self.log = logging.getLogger(self.__class__.__name__)

    @asyncio.coroutine
    def __call__(self, request):
        """
        This is the entrypoint that the aiohttp framework uses.

        Because of this, it has to be an asyncio coroutine.

        """

        # If disabled, skip authorization part.
        if self.disabled:
            return self.handler(request)

        return self.handle_handshake(request)

    def handle_handshake(self, request):
        if request._path == self.CHAP_PATH:
            try:
                return self.handshake_path(request)
            except Exception:
                raise web.HTTPForbidden()

        return self.handle_authorization(request)

    def handle_authorization(self, request):
        username = None
        authorization = request.headers.get(self.AUTHORIZATION_HEADER, None)

        if authorization and authorization.startswith("chap:"):
            _, token = authorization.split(":", 1)

            try:
                # The WSGI implementation sets the header self.AUTH_ENVIRON
                # on the request. This is not possible in aiohttp since the
                # headers are immutable. There doesn't seem to be a reason
                # to set it, since the resource we're accessing should not
                # need to care about the authentication data.
                username = self.auth_server.validate_token(token)
                self.log.info('Authenticated for user {0}'.format(username))

            except Exception:
                self.log.warning("Failed to validate token")
                raise web.HTTPForbidden()

        if not username and not self.manual_authorization:
            raise web.HTTPForbidden()

        # If all the way down here, then we are authenticated and ready to go!
        return self.handler(request)

    def handshake_path(self, request):
        """
        Client is in the handshake phase.

        Expect that the X-CHAP header is set, otherwise raise 403 Forbidden.

        Perform the required step as specified for the X-CHAP header, or fail
        with handle_auth_server_exception.

        """

        chap_header = request.headers.get(self.CHAP_HEADER, None)

        if chap_header is None:
            raise web.HTTPForbidden()

        method, value = chap_header.split(":", 1)

        if method == "request":
            return self.handle_request(request, value)

        if method == "response":
            return self.handle_response(request, value)

        self.log.warning("Unknown chap method: " + method)
        raise web.HTTPForbidden()

    def handle_request(self, request, value):
        username, version = parse_request(value)
        try:
            challenge = self.auth_server.create_challenge(username, version)

        except Exception:
            self.log.warning("Failed to create challenge")
            raise web.HTTPForbidden()

        return web.Response(
            status=200,
            headers={self.CHAP_HEADER: "challenge:" + challenge}
        )

    def handle_response(self, request, value):
        try:
            token = self.auth_server.create_token(value)

        except NoSuchUserException:
            self.log.info('No user found for data sent')
            raise web.HTTPForbidden()

        except Exception:
            self.log.warning("Failed to create token", exc_info=sys.exc_info())
            raise web.HTTPForbidden()

        return web.Response(
            status=200,
            headers={self.CHAP_HEADER: "token:" + token}
        )

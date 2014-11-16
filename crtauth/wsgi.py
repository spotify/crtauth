# Copyright (c) 2013-2014 Spotify AB
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
from crtauth import ssh

log = logging.getLogger("crtauth.wsgi")


class CrtauthMiddleware(object):
    """
    An instance of this class acts as middleware that will handle crtauth
    HTTP authentication for connecting clients. Once a user is authenticated,
    the WSGI environ object will have a value for the key 'crtauth.username'
    that corresponds to the username of the authenticated user.

    By default, only properly authenticated requests will reach the wrapped
    WSGI application. If you want more fine grained control over which
    resources should be protected, use the manual_authorization constructor
    parameter which will hand over responsibility for returning the
    401 Unauthorized HTTP status to the wrapped application.

    Any exception thrown by the auth server will be logged and result in a
    "403 Forbidden" response.
    """
    CHAP_HEADER = "X-CHAP"
    CHAP_WSGI_HEADER = "HTTP_X_CHAP"
    AUTHORIZATION_HEADER = "HTTP_AUTHORIZATION"
    AUTHORIZATION_TYPE = "chap"

    STATUS_UNAUTHORIZED = '401 Unauthorized'
    STATUS_FORBIDDEN = '403 Forbidden'
    STATUS_INTERNAL_SERVER_ERROR = '500 Internal Server Error'
    STATUS_OK = '200 OK'
    
    CHAP_PATH = "/_auth"

    AUTH_ENVIRON = "crtauth.username"

    def __init__(self, app, auth_server, disabled=False,
                 manual_authorization=False):
        """
        Construct a WSGI middleware that authenticates it's users before
        passing on requests to the enclosed app.

        :param app: a WSGI application to wrap.
        :param auth_server: A configured crtauth.server.AuthServer instance.
        :param disabled: set to true if authentication is disabled.
        :param manual_authorization: set to true if this middleware should
         not require the user to be authenticated to pass along the request.
         In this case the app needs to take care to return status 401 when
         an unauthorized user attempts to access a protected resource unless
         the WSGI environ key 'crtauth.username' maps to an acceptable
         username.
        """

        self.app = app
        self.auth_server = auth_server
        self.disabled = disabled
        self.manual_authorization = manual_authorization

    def read_authorization(self, environ):
        return environ.get(self.AUTHORIZATION_HEADER, None)

    def __call__(self, environ, start_response):
        """
        Handle the request and make sure that CHAP authentication stages for the
        special path /_auth

        Also check for any existing outstanding authentication by reading the
        Authorization header for a token matching "chap:<token>".
        This token is validated using the auth_server associated with this
        middleware.

        environ - Request environment.
        start_response - WSGI invokable start_response.
        """
        # if disabled, skip authorization part.
        if self.disabled:
            return self.app(environ, start_response)

        return self.handle_handshake(environ, start_response)

    def handle_handshake(self, environ, start_response):
        if environ.get("PATH_INFO", "/") == self.CHAP_PATH:
            try:
                return self.handshake_path(environ, start_response)
            except:
                log.error("Error when handling request", exc_info=sys.exc_info())
                start_response(self.STATUS_INTERNAL_SERVER_ERROR, [])
                return []

        return self.handle_authorization(environ, start_response)

    def handle_authorization(self, environ, start_response):
        username = None
        authorization = self.read_authorization(environ)

        if authorization and authorization.startswith("chap:"):
            _, token = authorization.split(":", 1)

            try:
                username = self.auth_server.validate_token(token)
                environ.update({self.AUTH_ENVIRON: username})
            except:
                log.warning("Failed to validate token", exc_info=sys.exc_info())
                return self.handle_unauthorized(environ, start_response)

        if not username and not self.manual_authorization:
            return self.handle_unauthorized(environ, start_response)

        return self.app(environ, start_response)

    def handshake_path(self, environ, start_response):
        """
        Client is in the handshake phase.

        Expect that the X-CHAP header is set, otherwise raise 403 Forbidden.

        Perform the required step as specified for the X-CHAP header, or fail with
        handle_auth_server_exception.
        """
        chap_header = environ.get(self.CHAP_WSGI_HEADER, None)

        if chap_header is None:
            start_response(self.STATUS_FORBIDDEN, [])
            return []

        method, value = chap_header.split(":", 1)

        if method == "request":
            return self.handle_request(environ, start_response, value)

        if method == "response":
            return self.handle_response(environ, start_response, value)

        log.warning("Unknown chap method: " + method)
        return self.handle_auth_server_exception(environ, start_response)

    def handle_request(self, environ, start_response, request):
        username, version = self.parse_request(request)
        try:
            challenge = self.auth_server.create_challenge(username, version)
        except:
            log.warning("Failed to create challenge", exc_info=sys.exc_info())
            return self.handle_auth_server_exception(environ, start_response)

        start_response(self.STATUS_OK, [(self.CHAP_HEADER, "challenge:" + challenge)])
        return []

    def handle_response(self, environ, start_response, response):
        try:
            token = self.auth_server.create_token(response)
        except:
            log.warning("Failed to create token", exc_info=sys.exc_info())
            return self.handle_auth_server_exception(environ, start_response)

        start_response(self.STATUS_OK, [(self.CHAP_HEADER, "token:" + token)])
        return []

    def handle_auth_server_exception(self, environ, start_response):
        """
        Raise a "403 Forbidden" error to the client.
        """
        start_response(self.STATUS_FORBIDDEN, [])
        return ["Failed to authenticate user"]

    def handle_unauthorized(self, environ, start_response):
        start_response(self.STATUS_UNAUTHORIZED,
                       [("content-type", "text/plain")])
        return ["Unauthorized"]

    @staticmethod
    def parse_request(request):
        """
        This method contains logic to detect a v1 and beyond request and
        differentiate it from a version 0 request, which is just an ascii
        username. While all v1 requests are also valid usernames (the curse
        and blessing of base64 encoding) it is pretty unlikely that a username
        happens to also decode to a valid msgpack message with the correct
        magic values.

        @return a tuple containing username then version
        """
        binary = ssh.base64url_decode(request)
        if len(binary) < 4:
            return request, 0
        if ord(binary[0]) > 4 or binary[1] != 'q':
            # This code handles version values up to 4. Should give plenty
            # of time to forget all about the unversioned version 0
            return request, 0
        b = ord(binary[2])
        if (b < 0xa1 or b > 0xbf) and b != 0xd9:
            # third byte does not indicate a string longer than 0 and shorter
            # than 256 octets long (According to UTF_8 rfc3629, a unicode
            # char can encode to at most 4 UTF-8 bytes, and username values
            # in crtauth is limited to 64 characters, thus the max number of
            # bytes a username can be is 64 * 4 == 256
            return request, 0
        if b == 0xd9:
            username_start = 4
            username_len = ord(binary[3])
        else:
            username_start = 3
            username_len = ord(binary[2]) & 0x1f

        if len(binary) - username_start < username_len:
            # decoded string is too short
            return request, 0

        return binary[username_start:username_start + username_len], 1

# -*- coding: utf-8 -*-
# Copyright (c) 2013 Spotify AB
# Author: John-John Tedro <udoprog@spotify.com>
import sys
import logging

log = logging.getLogger('wsgi_crtauth')


class CrtauthMiddleware:
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
    
    CHAP_METHOD = "HEAD"
    CHAP_PATH = "/_auth"

    CHAP_REQUIRE = (CHAP_METHOD, CHAP_PATH)

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

    @staticmethod
    def read_environ(environ):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        return method, path

    def read_authorization(self, environ):
        return environ.get(self.AUTHORIZATION_HEADER, None)

    def __call__(self, environ, start_response):
        """
        Handle the request and make sure that CHAP authentication stages when the
        following criterias are met.

        * The request method is of type "HEAD"
        * The request path is /_auth

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
        method, path = self.read_environ(environ)

        if (method, path) == self.CHAP_REQUIRE:
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

    def handle_request(self, environ, start_response, principal):
        try:
            challenge = self.auth_server.create_challenge(principal)
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
        return []

    def handle_unauthorized(self, environ, start_response):
        start_response(self.STATUS_UNAUTHORIZED,
                       [("content-type", "text/plain")])
        return ["Unauthorized"]

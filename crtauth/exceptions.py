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


class CrtAuthError(Exception):
    """
    The base exception class for crtauth.
    """
    pass


class ProtocolError(CrtAuthError):
    """
    Raised for errors encountered whilst handling the crtauth protocol.
    """
    pass


class KeyError(CrtAuthError):
    """
    Raised for errors encountered whilst handling encryption keys.
    """
    pass


class SshAgentError(CrtAuthError):
    """
    Raised for errors encountered whilst dealing with the SSH agent.
    """
    pass


class AuthenticationError(CrtAuthError):
    """
    The base exception class for errors caused by the client side (invalid
    username, wrong response to challenge, etc.)
    """
    pass


class InvalidUsername(AuthenticationError):
    """
    Exception raised when a client requests a challenge for a non-existing
    user.
    """
    HTTP_CODE = 404

    def __init__(self, username):
        self.username = username

    def __str__(self):
        return "Could not find user '%s' in our systems" % self.username


class BadResponse(AuthenticationError):
    """
    Exception raised when a client requests a token with a bad
    challenge/response response.
    """
    HTTP_CODE = 403

    def __str__(self):
        return "Bad challenge/response response"


class InvalidInputException(Exception):
    """
    Thrown from create_token and validate_token if the token or response
    contains invalid data
    """
    pass


class NoSuchUserException(AuthenticationError):
    """There is no public key on file for the user"""
    pass


class InsufficientPrivilegesException(AuthenticationError):
    """
    The user attempting to authenticate is not a member of the required group.
    """


class MissingKeyException(AuthenticationError):
    """
    The user attempting to authenticate exists, but does not have her key on
    file.
    """
    pass


class TokenExpiredException(Exception):
    """Thrown if a token older than token_lifetime is provided"""
    pass


class ProtocolVersionError(Exception):
    """
    Thrown if either the server or the client is proposing a version of
    the protocol that is too old.
    """

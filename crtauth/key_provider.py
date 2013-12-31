# Copyright (c) 2011-2013 Spotify AB
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

import os
from crtauth import exceptions
from crtauth import rsa


class KeyProvider(object):
    """Provides PubKey instances based on username. Please note that the
    username provided is not sanity checked and may be provided by an
    untrusted user. """

    def get_key(self, username):
        """Get a PubKey instance from some underlying system"""
        raise NotImplementedError


class FileKeyProvider(KeyProvider):
    def __init__(self, dir):
        self.dir = dir

    def get_key(self, username):
        if "/" in username:
            raise exceptions.CrtAuthError("Don't trick me into opening files "
                                          "by having slash in username!")
        fn = "%s/%s_id_rsa.pub" % (self.dir, username)
        if not os.path.exists(fn):
            raise exceptions.NoSuchUserException()
        with open(fn, "r") as f:
            return rsa.RSAPublicKey(f.read())

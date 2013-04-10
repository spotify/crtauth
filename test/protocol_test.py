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
from crtauth import protocol


def test_serialize_token():
    token = protocol.Token(valid_from=1365084334, valid_to=1365084634,
                           username="noa")
    buf = protocol.Token.serialize(token)
    assert buf == "t\x00\x00\x00Q]\x88\xaeQ]\x89\xda\x00\x00\x00\x03noa\x00"


def test_deserialize_token():
    buf = "t\x00\x00\x00Q]\x8b\x17Q]\x8bU\x00\x00\x00\x04test"
    token = protocol.Token.deserialize(buf)
    assert token.username == 'test'
    assert token.valid_from == 1365084951

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
from crtauth import xdr_packing


packing = xdr_packing

ref_token = protocol.Token(
    valid_from=1365084334, valid_to=1365084634, username="noa")


def test_serialize_token():
    p = packing.Packer()
    p.pack_fstring(1, protocol.Token.__magic__)
    p.pack_uint(ref_token.valid_from)
    p.pack_uint(ref_token.valid_to)
    p.pack_string(ref_token.username)
    buf = p.get_buffer()

    ref_buf = ref_token.serialize(packing)

    assert buf == ref_buf


def test_deserialize_token():
    ref_buf = ref_token.serialize(packing)

    token = protocol.Token.deserialize(packing, ref_buf)

    assert token.username == ref_token.username
    assert token.valid_from == ref_token.valid_from
    assert token.valid_to == ref_token.valid_to

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


def to_i(int_or_single_char_string):
    if isinstance(int_or_single_char_string, int):
        return int_or_single_char_string
    return ord(int_or_single_char_string)


def constant_time_compare(x, y):
    """
    Compares two byte strings in a way such that execution time is constant
    regardless of how much alike the input values are, provided that they
    are of the same length.

    Comparisons between user input and secret data such as calculated
    HMAC values needs to be executed in constant time to avoid leaking
    information to the caller via the timing side channel.

    Params:
        x: the first byte string to compare
        y: the second byte string to compare
    Return: True if x and y are equal, else False
    """

    if len(x) != len(y):
        return False
    result = 0
    for x, y in zip(x, y):
        result |= to_i(x) ^ to_i(y)
    return result == 0


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

    binary = base64url_decode(request)
    if len(binary) < 4:
        return request, 0

    if to_i(binary[0]) > 4 or to_i(binary[1]) != 113:  # The letter 'q'
        # This code handles version values up to 4. Should give plenty
        # of time to forget all about the unversioned version 0
        return request, 0

    b = to_i(binary[2])
    if (b < 0xa1 or b > 0xbf) and b != 0xd9:
        # third byte does not indicate a string longer than 0 and shorter
        # than 256 octets long (According to UTF_8 rfc3629, a unicode
        # char can encode to at most 4 UTF-8 bytes, and username values
        # in crtauth is limited to 64 characters, thus the max number of
        # bytes a username can be is 64 * 4 == 256
        return request, 0

    if b == 0xd9:
        username_start = 4
        username_len = to_i(binary[3])
    else:
        username_start = 3
        username_len = to_i(binary[2]) & 0x1f

    if len(binary) - username_start < username_len:
        # decoded string is too short
        return request, 0

    return binary[username_start:username_start + username_len].decode('utf-8'), 1

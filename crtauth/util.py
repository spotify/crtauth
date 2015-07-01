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

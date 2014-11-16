# Copyright (c) 2014 Spotify AB
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
from wsgiref import simple_server


def application(_, start_response):
    response = "crtauth client version too old. Update your client\n"
    status = '403 Forbidden'
    response_headers = [('Content-Type', 'text/plain'),
                        ('Content-Length', str(len(response)))]
    start_response(status, response_headers)
    return response,


if __name__ == '__main__':
    simple_server.make_server('', 8080, application).serve_forever()

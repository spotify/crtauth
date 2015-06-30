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

import sys
from setuptools import setup
from setuptools.command.test import test as TestCommand

install_requires = (
    'msgpack-python>=0.4.0,<1.0.0a0',
    'six>=1.9.0,<2.0.0a0',
)

tests_require = (
    'pytest-cov',
    'pytest-cache',
    'tox',
)


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = [
            'test',
            '-v',
            '--cov=crtauth',
            '--cov-report=xml',
            '--cov-report=term-missing',
            '--result-log=pytest-results.log'
        ]
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)


setup(
    name='crtauth',
    version='0.99.3',
    description="A public key backed client/server authentication system",
    author='Noa Resare',
    author_email='noa@spotify.com',
    license='Apache-2.0',
    packages=['crtauth'],
    install_requires=install_requires,
    tests_require=tests_require,
    cmdclass={
        'test': PyTest,
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Operating System :: Unix',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ]
)

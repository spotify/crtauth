# crtauth - a public key backed client/server authentication system

The latest version of this software can be fetched from
[GitHub](https://github.com/spotify/crtauth).

crtauth is a system for authenticating a user to a centralized server. The
initial use case is to create a convenient authentication for command line
tools that interacts with a central server without resorting to authentication
using a shared secret, such as a password.

The code available in this project is written in Python. There is also a
Java version, implementing the same protocol available at
[https://github.com/spotify/crtauth-java](https://github.com/spotify/crtauth-java)

crtauth leverages the public key cryptography mechanisms that is commonly
used by ssh(1) to authenticate users to remote systems. The goal of the
system is to make the user experience as seamless as possible using the
ssh-agent program to manage access to encrypted private keys without asking
for a password each time the command is run

The name of the project is derived from the central concepts challenge,
response, token and authentication, while at the same time reminding us old
timers of the soon to be forgotten cathode ray tube screen technology.

## Using the library

For the server side functionality there is a high level API available in the
[wsgi](crtauth/wsgi.py) module. It provides wsgi middleware functionality
that can be used to protect a  service using the crtauth
authentication mechanism. [hello_world_server](example/hello_world_server) gives
a minimal example on how this API is used. If crtauth is to be used in a
non-WSGI environment, there is a lower level API available in the
[server](crtauth/server.py) module.

For clients an [authentication plugin for Python Requests](https://github.com/spotify/requests-crtauth)
is available. An example use of the [client](crtauth/client.py) module can be
seen in the [hello_world_client](example/hello_world_client) example.


## Technical details

This section gives big picture overview of how crtauth operates. For the
specifics of the protocol and it's messages, please see
[the specification](PROTOCOL.md).

Command line tools that connect to a central server to perform some action or
fetch some information can be a very useful thing. crtauth is currently specified
to work with HTTP as transport, but it is entirely possible to re-use 
that exposes information about servers using an HTTP-based API.

The basic operation of the protocol follows the following pattern

* The client requests a challenge from the server, providing a username.
* The server creates a challenge that gets sent back to the client.
* The client signs the challenge and returns the response to the server.
* The server verifies that the response is valid and if so it issues an access
  token to the client.
* The access token is provided to when calling protected services.
* The server validates that the token is valid and if so, provides access
  to the client.

The that implement this mechanism has two parts, one for the server and one
for the client. A server that wants to authenticate clients instantiates an
AuthServer instance (defined in the crtauth.server module) with a secret and
a KeyProvider instance as constructor arguments. The very simple FileKeyProvider
reads public keys from a filesystem directory using a filename pattern derived
from the username of the connecting user.

Once there is an AuthServer instance, it can generate a challenge string for
a specific user using the `create_challenge()` method.

The client part of the mechanism is also contained in the crtauth.server module,
in the `create_response()` function. It takes a challenge string provided by the
server and returns a response string suitable for sending back to the server.

The server in turn validates the response from the client and if it checks out
it returns an access token that can be used by the client to make authenticated
requests. This validation is done in the `create_token()` method of the AuthServer
class.

For subsequent calls to protected services, the provided access token can be
verified using the `validate_token()` method of the AuthServer instance.

## SSH keys from LDAP

This library also provides functionality to extract public ssh keys for
connecting users using an LDAP directory. To use this functionality, which
is available in the ldap_key_provider.py module, the python-ldap module needs
to be installed.

## License

crtauth is free software, this code is released under the Apache
Software License, version 2. The original code is written by Noa Resare with
contributions from John-John Tedro, Erwan Lemmonier, Martin Parm and Gunnar
Kreitz

All code is Copyright (c) 2011-2017 Spotify AB

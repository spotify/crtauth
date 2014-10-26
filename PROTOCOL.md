# The crtauth HTTP authentication protocol
version 1.0
by John-John Tedro (udoprog@spotify.com) and Noa Resare (noa@spotify.com)

## Introduction

This document defines version 1 of the crtauth HTTP authentication protocol.
Crtauth HTTP provides the ability for a client to authenticate with a server
using the widely available SSH public key mechanisms.

To authenticate using crtauth, the server needs to have access to the user's
public ssh key. Using that key, the server creates a challenge which is sent
to the user for signing. The user then uses her private key to sign the
challenge and sends the challenge back together with a signature. If the server
can validate the signature and thereby prove the identity of the user it issues
a token that can be used by the client to access protected resources.

While this specification concerns itself with using crtauth in an HTTP context
there is nothing inherent in crtauth that ties it to HTTP. Other standards
may specify how to use crtauth with other transport protocols.

crtauth was originally created by Noa Resare with help from Mattias Jansson.
The specifics of how to use crtauth HTTP and and initial version of this
specification was written by John-John Tedro and Martin Parm.

## Previous versions

An initial version 0 of the protocol was released and have been used, however
implementing this version is discouraged as it is missing version information
and uses older versions of various cryptographic methods.

## Overview

Authentication with the crtauth HTTP protocol is performed over http over
two requests; the *Challenge Request*  and the *Token Request*.

     C                         S
     |                         |
(1)  | ----------------------> | > Request to protected resource
     |                         |
     | <---------------------- | < 401 Unauthorized
     |                         |
(2)  | ----------------------> | > HEAD: /_auth              (Challenge Request)
     |                         | > X-CHAP: version:1,request:<username>
     |                         |
(3)  | <---------------------- | < X-CHAP: challenge:<challenge>
     |                         |
(4)  | ----------------------> | > HEAD: /_auth              (Token Request)
     |                         | > X-CHAP: response:<response>
     |                         |
(5)  | <---------------------- | < X-CHAP: token:<token>
     |                         |   or: 403 Forbidden
     |                         |
     | ----------------------> | > Request to protected resource
     |                         | > Authorization: chap:<token>
     |                         |
(6)  | <---------------------- | < any HTTP Resource
     |                         | < or: 401 Unauthorized

     figure 1. Protocol Flow

The term CHAP used in the headers is an acronym for Challenge Handshake
Authentication Protocol.

When a server receives a request for a protected resource without an
Authorization header it returns the HTTP status code "401 Unauthorized" (1)

This prompts the client to issue an HTTP HEAD request using the special path
"/_auth" with header X-CHAP indicating the version of the protocol as well as
the username of the user that wishes to authenticate. (2)

The server then returns a HTTP response with an X-CHAP header containing a
challenge string (3). The client then signs the contents of the response
string and returns the response message containing the challenge plus a
cryptographic signature that proves that the user sign data using the
appropriate private key. (4)

Once the server has validated the signature using the user's public key it
may issue a short lived token string (5) that the user can use to prove it's
identity and gain access to protected resources on the server (6).

## Transport

Since the crtauth HTTP protocol doesn't make any attempts to validate the
identity of the server, communication MUST be protected by TLS and the
client MUST properly validate the certificate that the server provides.



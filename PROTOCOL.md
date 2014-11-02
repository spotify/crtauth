# The crtauth HTTP authentication protocol
#### version 1.0
#### by John-John Tedro (udoprog@spotify.com) and Noa Resare (noa@spotify.com)

## Introduction

This document defines version 1 of the crtauth HTTP authentication protocol.
Crtauth HTTP provides the ability for a client to authenticate with a server
using the widely available SSH public key mechanisms.

To authenticate using crtauth, the server needs to have access to the user's
public ssh key. Using that key, the server creates a challenge which is sent
to the user for signing. The user then uses her private key to sign the
challenge and sends the challenge back together with a signature.
If the server can validate the signature and thereby prove the identity of the
user it issues a token that can be used by the client to access protected
resources.

While this specification concerns itself with using crtauth in an HTTP context
there is nothing inherent in crtauth that ties it to HTTP.
Other standards may specify how to use crtauth with other transport protocols.

crtauth was originally created by [Noa Resare](mailto:noa@spotify.com) with
help from [Mattias Jansson](mailto:fimblo@spotify.com).
The specifics of how to use crtauth HTTP and and initial version of this
specification was written by [John-John Tedro](mailto:udoprog@spotify.com) and
[Martin Parm](mailto:parmus@spotify.com).

## Previous versions

An initial version 0 of the protocol was released and have been used, however
implementing this version is discouraged as it is missing version information
and uses older versions of various cryptographic methods.

## Overview

```
     C                         S
     |                         |
(1)  | ----------------------> | > Request to protected resource
     |                         |
     | <---------------------- | < 401 Unauthorized
     |                         |
(2)  | ----------------------> | > GET: /_auth              (Challenge Request)
     |                         | > X-CHAP: request:<request>
     |                         |
(3)  | <---------------------- | < X-CHAP: challenge:<challenge>
     |                         |
(4)  | ----------------------> | > GET: /_auth              (Token Request)
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
```

The term CHAP used in the headers is an acronym for Challenge Handshake
Authentication Protocol.

If a server receives a request for a protected resource with a missing, or
invalid `Authorization` header it MUST return the HTTP status code
`401 Unauthorized` as per [RFC2616 section 10.4.2][RFC2616] `(1)`.

This prompts the client to issue an HTTP GET request as per
[RFC2616 section 9.4][RFC2616] using the special request uri `/_auth` with
an `X-CHAP` header indicating the version of the protocol as well as the
username of the user that is to be be authenticated `(2)`.

The server then returns a HTTP response with an `X-CHAP` header containing a
challenge string `(3)`.
The client then signs the contents of the response string and returns the
response message containing the challenge plus a cryptographic signature that
proves that the user sign data using the appropriate private key `(4)`.

Once the server has validated the signature using the public key of a user it
MAY issue a short lived token string `(5)` that the user can use to prove
its identity and gain access to protected resources on the server for future
requests `(6)`.

## Transport

Since the crtauth HTTP protocol doesn't make any attempts to validate the
identity of the server, communication MUST be protected by TLS and the
client SHOULD use current best practices to establish the identity of the
server.
If an attacker were to successfully masquerade as the server it could launch a
man-in-the-middle attack to extract a token and use it to access protected
resources from the real server.

## Handling the case of unknown usernames

To avoid indicating to a calling client whether the server knows about an
account or not, the server should return a fully valid challenge message where
the public key fingerprint is a function of the provided username.
To accomplish this, the fingerprint should be the first 6 bytes of the HMAC
code generated for the provided username using the server secret as key.

## Supported public key algorithm

The supported algorithm for public key cryptography used in this standard is
RSA. No other standard can be used.

## Messages

Messages are encoded using the msgpack format, with some additional
restrictions.
Each message MUST be encoded using the shortest possible format.
The bin format family MUST be used for binary data. The binary messages are
then encoded in URL compatible Base64 format with an URL and Filename safe
alphabet as defined [RFC3548][RFC3548] section 4.
The last two characters being `'-'` and `'_'`.
The padding characters at the end of Base64 encoded data MAY be omitted.

The order of the fields of each messages is significant, as the fields are
identified by the order in which they occur.

All messages begin with an integer value that identifies the version of the
protocol the message is conforming to.
This value should always be 1 for messages conforming to this specification.
Following this value is a magic value, an integer value that identifies the
type of message.
There are four possible values, for the four types of messages.

* `0x71` (ASCII `q`) for [Request](#request).
* `0x63` (ASCII `c`) for [Challenge](#challenge).
* `0x72` (ASCII `r`) for [Response](#response).
* `0x74` (ASCII `t`) for [Token](#token).

### Request

A `Request` message contains the following fields

| Field         | Type       | Comment                      |
| ------------- |------------|------------------------------|
| version       | int family | Always `0x01`                |
| magic         | int family | Always `0x71` (ASCII `q`)    |
| username      | str family | The username                 |

The username MUST be 64 characters long or shorter and MAY contain characters
outside of the ASCII range. As msgpack strings are, username values are encoded
using the UTF-8 encoding.

### Challenge

A `Challenge` message contains the following fields

| Field         | Type       | Comment                      |
| ------------- |------------|------------------------------|
| version       | int family | Always `0x01`                |
| magic         | int family | Always `0x63` (ASCII `c` ) |
| unique data   | bin 8      | 20 bytes of random data      |
| valid from    | int family | Start of validity period     |
| valid to      | int family | End of validity period       |
| fingerprint   | bin 8      | 6 bytes identifying pubkey   |
| server name   | str family | FQDN of server               |
| username      | str family | The username                 | 
| hmac code     | bin family | Server integrity check value |

The purpose of the random data in the *unique data* field is to ensure that
each request is unique and that an attacker can not re-use a signature for a
new request.

The validity fields hold a UNIX second value, the number of non-leap seconds
since midnight, January 1 1970 UTC. Responses that sign challenges where the
*valid from* value is in the future or the *valid to* value is in the past is
invalid and MUST be rejected.

The *fingerprint* bytes consists of the 6 first bytes of a SHA-1 hash of the
traditional binary representation of an RSA key used by ssh-keygen: a simple
length value encoding with a 4 byte big endian length followed by the value
as a binary number of first the public exponent followed by the modulus.

The *server name* MUST be 255 characters of length or shorter and follow the
character sets of domain names (characters, numbers, hyphen (-) and dot (.)).

The client MUST verify that the *server name* of the challenge to be signed
matches the host that it connected to when requesting the challenge, to prevent
man-in-the-middle attacks.

The *hmac code* is created by the server using a secret that only it holds and
is used to verify that the response contains a challenge that was created by
the server. The *hmac code* is created as described in [RFC4634][RFC4634] using
SHA256 as hash algorithm.

### Response

| Field         | Type       | Comment                      |
| ------------- |------------|------------------------------|
| version       | int family | Always `0x01`                |
| magic         | int family | Always `0x72` (ASCII `r`)    |
| payload       | bin family | The full Challenge           |
| signature     | bin family | The signature of the payload |

The signature is created using the RSA algorithm as described in
[RFC3447][RFC3447] using SHA1 as hash algorithm.
Although it would have been preferable to have a more modern hash algorithm,
this is chosen because widely distributed ssh-agent versions have support for
this signature variant built in.

If the client has more than one RSA private key to chose from it MAY use the
data in the fingerprint field of the challenge to identify the correct key.

### Token

| Field         | Type            | Comment                      |
| ------------- |-----------------|------------------------------|
| version       | positive fixint | Always `0x01`                |
| magic         | positive fixint | Always `0x74` (ASCII `t`)    |
| valid from    | uint family     | Start of validity period     |
| valid to      | uint family     | End of validity period       |
| username      | str family      | The username                 | 
| hmac code     | bin family      | Server integrity check value |

## HTTP Headers

The messages of an crtauth HTTP exchange is sent via the `X-CHAP` HTTP
extension header or the Authorization HTTP header.
All messages described below are encoded as described in the Messages section
above.

The X-CHAP header has a value of the format *method : message*

### X-CHAP: `request:<request>`

The request is a message of type [Request](#request) as defined above, and
sent by a client to initially request a `<challenge>`.

### X-CHAP: `challenge:<challenge>`

The challenge is a message of type [Challenge](#challenge) as defined above,
and is sent by the server as a reply to a `<request>`.

### X-CHAP: `response:<response>`

The response is a message of type [Response](#response) as defined above,
and is sent by the client as a reply to a `<challenge>`.

### X-CHAP: `token:<token>`

The token is a message of type [Token](#token) as defined above,
and is sent by the server as a reply to a `<response>`.

The `<token>` MUST be included in is in further client communication supplied in
the HTTP ```Authorization``` header.
The header MUST have the format `chap:<token>`, where `"chap:"` is literal
ASCII.

## Handling future versions of the protocol

Individual messages are all versioned to 1 in messages conforming to this
specification.
Future versions of this protocol MAY send `Request` messages with higher
version numbers than 1, in which case they MAY add additional data to the
`Request` after the *user name* field.
Those pieces of data is ignored by conforming implementations, which will treat
the `Request` message as if it was version 1 and ignore any additional data.

Subsequent messages with version values higher than 1 SHOULD be rejected by
the receiver conforming to this specification.
This means that a client that conforms to a later version of the protocol needs
to keep track of the fact that the `Challenge` message sent back as an answer
to the `Request` message has version set to 1 and emit version 1 messages for
the subsequent conversation.

If for some reason, a later server chooses to cease support for a certain
version of the protocol, any messages sent with that version should be
responded to with an HTTP status code `400 Bad Request` as per
[RFC2616 section 10.4.1][RFC2616].

The body of the HTTP message SHOULD contain a `text/plain` human readable
message that the client can relay to the end user informing, for example, of
the reason for the refusal.


  [RFC3548]: https://www.ietf.org/rfc/rfc3548.txt
  [RFC4634]: https://www.ietf.org/rfc/rfc4634.txt
  [RFC3447]: https://www.ietf.org/rfc/rfc3447.txt
  [RFC2616]: https://www.ietf.org/rfc/rfc2616.txt

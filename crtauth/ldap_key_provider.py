# Copyright (c) 2011-2014 Spotify AB
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
from crtauth import exceptions, rsa, key_provider
import ldap
from ldap import filter


class LDAPKeyProvider(key_provider.KeyProvider):
    """
    Provides a PubKey instance based on a lookup in an LDAP directory.

    User entries are expected to be of class posixAccount living directly under
    base_dn in the directory information tree, have an uid matching the
    username parameter and one sshPublicKey string representation
    of the ssh public key of the user.

    Group entries are expected to be of class posixGroup and be located under
    cn=groups under the base_dn in the directory information tree. The group
    string parameter corresponds to the cn attribute of the posixGroup entry
    """
    def __init__(self, uri, auth_user, auth_password, base_dn, group=None):
        """
        Constructs and binds an LDAPKeyProvider instance to the server
        identified by the uri using auth_user and auth_password for
        authentication.

        When users are looked up, it is verified that they belong to the
        provided group.
        """
        self.group = None
        if group:
            self.group = filter.escape_filter_chars(group)
        self.base_dn = base_dn

        # I know, this is not functionality the ldap module straightforwardly
        # exposes, but it seems to work.
        self.conn = ldap.ldapobject.ReconnectLDAPObject(uri)
        self.conn.simple_bind(auth_user, auth_password)

    def get_key(self, username):
        """
        Returns a PubKey instance based on LDAP lookup. If group is specified
        in the constructor, the user needs to be a member for the lookup to
        succeed.

        Throws NoSuchUserException, InsufficientPrivilegesException,
        MissingKeyException when appropriate.
        """

        user = filter.escape_filter_chars(username)
        f = ("(|(&(uid=%s)(objectClass=posixAccount))"
             "(&(memberUid=%s)(objectClass=posixGroup)))" % (user, user))

        # We don't care about looking for a group if self.group is not set
        group_dn = None
        if self.group:
            group_dn = "cn=%s,cn=groups,%s" % (self.group, self.base_dn)

        result = dict(self.conn.search_s(self.base_dn, ldap.SCOPE_SUBTREE, f,
                                         ['sshPublicKey']))

        attributes = result.get("uid=%s,cn=users,%s" % (user, self.base_dn))
        if attributes is None:
            raise exceptions.NoSuchUserException("User '%s' not found" % user)

        key_list = attributes.get("sshPublicKey")
        if key_list is None:
            raise exceptions.MissingKeyException("User '%s' does not have "
                                                 "her key in LDAP" % user)
        if len(key_list) > 1:
            raise RuntimeError("Can't handle multiple sshPublicKey values "
                               "for an LDAP user")

        if group_dn and group_dn not in result:
            s = ("User '%s' not member of required group '%s'" %
                 (user, self.group))
            raise exceptions.InsufficientPrivilegesException(s)

        return rsa.RSAPublicKey(key_list[0])


class HybridKeyProvider(key_provider.KeyProvider):
    """
    A KeyProvider that behaves as an LDAP KeyProvider if there is no ldap data
    it falls back to a FileKeyProvider.
    Useful for non mixing real ldap users with service-specific non-human
    users.
    """

    def __init__(self, dir, uri, auth_user, auth_password, base_dn, group=None):
        """
        Constructs a FileKeyProvider based on the directory dir, and a
        LDAPKeyProvider based on the remaining arguments.
        """
        self.file_key_provider = key_provider.FileKeyProvider(dir)
        self.ldap_key_provider = LDAPKeyProvider(uri, auth_user, auth_password,
                                                 base_dn, group)

    def get_key(self, username):
        """
        Returns the user's public key if it can be found in LDAP, otherwise
        tries to find it in the key directory, or fails.
        """
        try:
            return self.ldap_key_provider.get_key(username)
        except exceptions.NoSuchUserException:
            try:
                return self.file_key_provider.get_key(username)
            except Exception, e:
                raise exceptions.NoSuchUserException(
                    "User %s not in ldap, defaulted to pubkey dir and got "
                    "exception %s" % (username, e))

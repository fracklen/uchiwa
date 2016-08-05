// Copyright (c) Jerome Touffe-Blin ("Author")
// All rights reserved.

// The BSD License

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:

// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.

// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.

// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
// BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
// BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
// OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
// IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Thanks to https://github.com/jtblin/go-ldap-client

// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package ldap

import (
    "crypto/tls"
    "errors"
    "fmt"
    "gopkg.in/ldap.v2"
)

type LDAPClient struct {
    Conn         *ldap.Conn
    Host         string
    Port         int
    UseSSL       bool
    BindDN       string
    BindPassword string
    GroupFilter  string // e.g. "(memberUid=%s)"
    UserFilter   string // e.g. "(uid=%s)"
    Base         string
    Attributes   []string
}

// Connect connects to the ldap backend
func (lc *LDAPClient) Connect() error {
    if lc.Conn == nil {
        var l *ldap.Conn
        var err error
        address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
        if !lc.UseSSL {
            l, err = ldap.Dial("tcp", address)
            if err != nil {
                return err
            }

            // Reconnect with TLS
            err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
            if err != nil {
                return err
            }
        } else {
            l, err = ldap.DialTLS("tcp", address, &tls.Config{InsecureSkipVerify: false})
            if err != nil {
                return err
            }
        }

        lc.Conn = l
    }
    return nil
}

// Close closes the ldap backend connection
func (lc *LDAPClient) Close() {
    if lc.Conn != nil {
        lc.Conn.Close()
        lc.Conn = nil
    }
}

// Authenticate authenticates the user against the ldap backend
func (lc *LDAPClient) Authenticate(username, password string) (bool, map[string]string, []string, error) {
    err := lc.Connect()
    if err != nil {
        return false, nil, []string{}, err
    }

    // First bind with a read only user
    if lc.BindDN != "" && lc.BindPassword != "" {
        err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
        if err != nil {
            return false, nil, []string{}, err
        }
    }

    attributes := append(lc.Attributes, "dn")
    // Search for the given username
    searchRequest := ldap.NewSearchRequest(
        lc.Base,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        fmt.Sprintf(lc.UserFilter, username),
        attributes,
        nil,
    )

    sr, err := lc.Conn.Search(searchRequest)
    if err != nil {
        return false, nil, []string{}, err
    }

    if len(sr.Entries) < 1 {
        return false, nil, []string{}, errors.New("User does not exist")
    }

    if len(sr.Entries) > 1 {
        return false, nil, []string{}, errors.New("Too many entries returned")
    }

    userDN := sr.Entries[0].DN
    user := map[string]string{}

    for _, attr := range lc.Attributes {
        user[attr] = sr.Entries[0].GetAttributeValue(attr)
    }
    groups := sr.Entries[0].GetAttributeValues("memberOf")

    // Bind as the user to verify their password
    err = lc.Conn.Bind(userDN, password)
    if err != nil {
        return false, user, groups, err
    }

    // Rebind as the read only user for any further queries
    if lc.BindDN != "" && lc.BindPassword != "" {
        err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
        if err != nil {
            return true, user, groups, err
        }
    }

    return true, user, groups, nil
}

// GetGroupsOfUser returns the group for a user
func (lc *LDAPClient) GetGroupsOfUser(username string) ([]string, error) {
    err := lc.Connect()
    if err != nil {
        return nil, err
    }

    searchRequest := ldap.NewSearchRequest(
        lc.Base,
        ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
        fmt.Sprintf(lc.GroupFilter, username),
        []string{"cn"}, // can it be something else than "cn"?
        nil,
    )
    sr, err := lc.Conn.Search(searchRequest)
    if err != nil {
        return nil, err
    }
    groups := []string{}
    for _, entry := range sr.Entries {
        groups = append(groups, entry.GetAttributeValue("cn"))
    }
    return groups, nil
}

package authentication

import(
    "fmt"
    "github.com/fracklen/uchiwa/uchiwa/logger"
    "github.com/fracklen/uchiwa/uchiwa/authentication/ldap"
)

var (
    ldapClient ldap.LDAPClient
    ldapRequireGroup string
)

func ldap_auth(u, p string) (*User, error) {
    // It is the responsibility of the caller to close the connection
    defer ldapClient.Close()

    ok, user, groups, err := ldapClient.Authenticate(u, p)
    if err != nil {
        logger.Warningf("Error authenticating user %s: %+v", "username", err)
        return &User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
    }
    if !ok {
        logger.Warningf("Authenticating failed for user %s", "username")
        return &User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
    }
    logger.Infof("User: %+v", user)

    // groups, err := ldapClient.GetGroupsOfUser(fmt.Sprintf("%+v",user["uidNumber"]))
    // if err != nil {
    //     logger.Warningf("Error getting groups for user %s: %+v", "username", err)
    //     return &User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
    // }
    // logger.Infof("Groups: %+v", groups)
    for _, memberships := range groups {
        if memberships == ldapRequireGroup {
            retuser := User{}
            retuser.Username = u
            return &retuser, nil
        }
    }

    logger.Warningf("User not in required group: %s, %+v", u, groups)
    return &User{}, fmt.Errorf("User not in required group: %s, %+v", u, groups)
}


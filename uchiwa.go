package main

import (
	"flag"
	"github.com/fracklen/uchiwa/uchiwa"
	"github.com/fracklen/uchiwa/uchiwa/audit"
	"github.com/fracklen/uchiwa/uchiwa/authentication"
	"github.com/fracklen/uchiwa/uchiwa/authorization"
	"github.com/fracklen/uchiwa/uchiwa/config"
	"github.com/fracklen/uchiwa/uchiwa/filters"
)

func main() {
	configFile := flag.String("c", "./config.json", "Full or relative path to the configuration file")
	configDir := flag.String("d", "", "Full or relative path to the configuration directory, or comma delimited directories")
	publicPath := flag.String("p", "public", "Full or relative path to the public directory")
	flag.Parse()

	config := config.Load(*configFile, *configDir)

	u := uchiwa.Init(config)

	auth := authentication.New(config.Uchiwa.Auth)

	switch config.Uchiwa.Auth.Driver {
	case "simple":
		auth.Simple(config.Uchiwa.Users)
	case "ldap":
		auth.Ldap(config.GetLdapClient(), config.Uchiwa.Ldap.RequireGroup)
	default:
		auth.None()
	}


	// Audit
	audit.Log = audit.LogMock

	// Authorization
	uchiwa.Authorization = &authorization.Uchiwa{}

	// Filters
	uchiwa.Filters = &filters.Uchiwa{}

	u.WebServer(publicPath, auth)
}

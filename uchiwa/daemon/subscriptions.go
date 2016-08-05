package daemon

import (
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/fracklen/uchiwa/uchiwa/helpers"
	"github.com/fracklen/uchiwa/uchiwa/logger"
	"github.com/fracklen/uchiwa/uchiwa/structs"
)

// BuildSubscriptions builds a slice of every client subscriptions
func (d *Daemon) BuildSubscriptions() {
	for _, client := range d.Data.Clients {
		var generic structs.GenericClient
		err := mapstructure.Decode(client, &generic)
		if err != nil {
			logger.Debug("%s", err)
			continue
		}

		for _, subscription := range generic.Subscriptions {
			// Do not add per-client subscriptions to the slice so we don't pollute
			// the subscriptions filter in the frontend.
			// See https://github.com/fracklen/sensu-settings/pull/40.
			if strings.HasPrefix(strings.ToLower(subscription), "client:") {
				continue
			}

			if !helpers.IsStringInArray(subscription, d.Data.Subscriptions) {
				d.Data.Subscriptions = append(d.Data.Subscriptions, subscription)
			}
		}
	}
}

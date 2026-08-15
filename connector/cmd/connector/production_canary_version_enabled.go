//go:build productioncanary

package main

import "github.com/peter2317238492/sub2api-codex-control/connector/internal/config"

func connectorBinaryVersion() string {
	return config.DefaultConnectorVersion + "+productioncanary"
}

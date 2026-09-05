//go:build !productioncanary

package auth

import "net/http"

func productionCanaryRejection(*http.Response, string) error { return nil }

func productionCanaryHTTPClient(client *http.Client) *http.Client { return client }

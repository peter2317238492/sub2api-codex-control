//go:build !productioncanary

package auth

import "net/http"

func productionCanaryRejection(*http.Response, string) error { return nil }

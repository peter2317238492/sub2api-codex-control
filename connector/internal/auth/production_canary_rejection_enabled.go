//go:build productioncanary

package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

var ErrInvalidDeviceCredential = errors.New("device token exchange returned HTTP status 401: invalid device credential")

func productionCanaryRejection(response *http.Response, expectedURL string) error {
	if response.StatusCode != http.StatusUnauthorized || response.Header.Get("WWW-Authenticate") != "Device" ||
		response.Request == nil || response.Request.URL == nil || response.Request.URL.String() != expectedURL ||
		response.Request.Response != nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return nil
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil || compact.String() != `{"detail":"invalid_device_credential"}` {
		return nil
	}
	return ErrInvalidDeviceCredential
}

//go:build darwin || linux

package wspath

import "strings"

func toRemote(local string) (string, error) {
	if err := validatePOSIX(local); err != nil {
		return "", err
	}
	return local, nil
}

func toLocal(remote string) (string, error) {
	if err := validatePOSIX(remote); err != nil {
		return "", err
	}
	return remote, nil
}

func pathEqual(a, b string) bool { return a == b }

func pathHasPrefix(child, prefix string) bool { return strings.HasPrefix(child, prefix) }

func toRemotePattern(local string) (string, error) { return toRemote(local) }

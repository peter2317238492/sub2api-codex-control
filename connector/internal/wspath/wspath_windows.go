//go:build windows

package wspath

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	uncPrefix         = "unc"
	reservedRunes     = `<>:"|?*\/`
	cstrEqual         = 2
	compareIgnoreCase = 1
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procCompareStringOrdinal = kernel32.NewProc("CompareStringOrdinal")
)

var reservedDeviceNames = map[string]struct{}{
	"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
	"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {},
	"COM6": {}, "COM7": {}, "COM8": {}, "COM9": {},
	"LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {},
	"LPT6": {}, "LPT7": {}, "LPT8": {}, "LPT9": {},
}

func toRemote(local string) (string, error) { return toRemoteWith(local, false) }

func toRemotePattern(local string) (string, error) { return toRemoteWith(local, true) }

func toRemoteWith(local string, allowGlob bool) (string, error) {
	if local == "" {
		return "", errors.New("path is empty")
	}
	if len(local) > MaxPathBytes {
		return "", fmt.Errorf("path exceeds %d bytes", MaxPathBytes)
	}
	normalized := strings.ReplaceAll(local, "/", `\`)
	var remote string
	switch {
	case strings.HasPrefix(normalized, `\\`):
		components, err := splitLocal(normalized[2:], allowGlob)
		if err != nil {
			return "", err
		}
		if len(components) < 3 {
			return "", errors.New("path is a UNC share root")
		}
		remote = "/" + uncPrefix + "/" + strings.Join(components, "/")
	case len(normalized) > 2 && isDriveLetter(normalized[0]) && normalized[1] == ':' && normalized[2] == '\\':
		components, err := splitLocal(normalized[3:], allowGlob)
		if err != nil {
			return "", err
		}
		if len(components) == 0 {
			return "", errors.New("path is a volume root")
		}
		remote = "/" + strings.ToLower(normalized[:1]) + "/" + strings.Join(components, "/")
	default:
		return "", errors.New("path is not an absolute Windows path")
	}
	if err := validatePOSIX(remote); err != nil {
		return "", err
	}
	return remote, nil
}

func toLocal(remote string) (string, error) {
	if err := validatePOSIX(remote); err != nil {
		return "", err
	}
	if strings.ContainsRune(remote, '\\') {
		return "", errors.New("path contains a backslash")
	}
	components := strings.Split(remote[1:], "/")
	for _, component := range components {
		if err := validateComponent(component); err != nil {
			return "", err
		}
	}
	var local string
	switch {
	case components[0] == uncPrefix:
		if len(components) < 4 {
			return "", errors.New("path is a UNC share root")
		}
		local = `\\` + strings.Join(components[1:], `\`)
	case len(components[0]) == 1 && isDriveLetter(components[0][0]):
		if len(components) < 2 {
			return "", errors.New("path is a volume root")
		}
		local = strings.ToUpper(components[0]) + `:\` + strings.Join(components[1:], `\`)
	default:
		return "", errors.New("path names no Windows volume")
	}
	projected, err := toRemote(local)
	if err != nil {
		return "", fmt.Errorf("path does not project back: %w", err)
	}
	if projected != remote {
		return "", errors.New("path is not the canonical projection of a local path")
	}
	return local, nil
}

func splitLocal(rest string, allowGlob bool) ([]string, error) {
	rest = strings.TrimSuffix(rest, `\`)
	if rest == "" {
		return nil, nil
	}
	components := strings.Split(rest, `\`)
	for _, component := range components {
		if err := validateComponentWith(component, allowGlob); err != nil {
			return nil, err
		}
	}
	return components, nil
}

func validateComponent(component string) error { return validateComponentWith(component, false) }

func validateComponentWith(component string, allowGlob bool) error {
	if component == "" {
		return errors.New("path component is empty")
	}
	if component == "." || component == ".." {
		return errors.New("path component is a relative reference")
	}
	if strings.HasSuffix(component, " ") || strings.HasSuffix(component, ".") {
		return errors.New("path component ends in a space or a dot")
	}
	for _, character := range component {
		if character < 0x20 {
			return errors.New("path component contains a control character")
		}
		if strings.ContainsRune(reservedRunes, character) {
			// A glob pattern is matched, never opened, so the metacharacters
			// that would make a filename invalid are meaningful in one.
			if allowGlob && (character == '*' || character == '?') {
				continue
			}
			return fmt.Errorf("path component contains the reserved character %q", character)
		}
	}
	stem := component
	if index := strings.IndexByte(stem, '.'); index >= 0 {
		stem = stem[:index]
	}
	if _, reserved := reservedDeviceNames[strings.ToUpper(stem)]; reserved {
		return errors.New("path component is a reserved DOS device name")
	}
	return nil
}

func isDriveLetter(character byte) bool {
	return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')
}

func pathEqual(a, b string) bool {
	first, second, ok := utf16Pair(a, b)
	if !ok {
		return false
	}
	return equalOrdinal(first, second)
}

func pathHasPrefix(child, prefix string) bool {
	first, second, ok := utf16Pair(child, prefix)
	if !ok {
		return false
	}
	if len(second) > len(first) {
		return false
	}
	return equalOrdinal(first[:len(second)], second)
}

func utf16Pair(a, b string) ([]uint16, []uint16, bool) {
	first, err := syscall.UTF16FromString(a)
	if err != nil {
		return nil, nil, false
	}
	second, err := syscall.UTF16FromString(b)
	if err != nil {
		return nil, nil, false
	}
	return first[:len(first)-1], second[:len(second)-1], true
}

// equalOrdinal defers to the uppercasing table Windows itself uses to compare
// file names. strings.EqualFold folds code points such as U+212A and U+017F
// that the filesystem keeps distinct, which would let a sibling directory pass
// a containment check. A failed comparison reports "not equal".
func equalOrdinal(first, second []uint16) bool {
	if len(first) != len(second) {
		return false
	}
	if len(first) == 0 {
		return true
	}
	result, _, _ := procCompareStringOrdinal.Call(
		uintptr(unsafe.Pointer(&first[0])),
		uintptr(len(first)),
		uintptr(unsafe.Pointer(&second[0])),
		uintptr(len(second)),
		compareIgnoreCase,
	)
	runtime.KeepAlive(first)
	runtime.KeepAlive(second)
	return result == cstrEqual
}

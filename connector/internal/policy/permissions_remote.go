package policy

import (
	"errors"
	"fmt"
)

// RemotePermissions returns a deep copy of a validated permission profile with
// every filesystem path projected into the remote POSIX form.
//
// The validated profile itself is what goes back to app-server, so it must not
// be modified in place; the browser needs the projected form because the
// Control API only ever speaks POSIX paths. The shape accepted here is exactly
// what Guard.ValidatePermissions produces — anything else fails closed rather
// than being copied through unprojected.
func RemotePermissions(validated map[string]any) (map[string]any, error) {
	if validated == nil {
		return nil, errors.New("validated permissions are unavailable")
	}
	remote := make(map[string]any, len(validated))
	for key, value := range validated {
		switch key {
		case "network":
			network, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("network permissions are invalid")
			}
			copied := make(map[string]any, len(network))
			for name, setting := range network {
				copied[name] = setting
			}
			remote[key] = copied
		case "fileSystem":
			fileSystem, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("filesystem permissions are invalid")
			}
			projected, err := remoteFileSystemPermissions(fileSystem)
			if err != nil {
				return nil, err
			}
			remote[key] = projected
		default:
			return nil, fmt.Errorf("permission field %q is not allowed", key)
		}
	}
	return remote, nil
}

func remoteFileSystemPermissions(fileSystem map[string]any) (map[string]any, error) {
	projected := make(map[string]any, len(fileSystem))
	for key, value := range fileSystem {
		switch key {
		case "read", "write":
			if value == nil {
				projected[key] = nil
				continue
			}
			paths, ok := permissionPaths(value)
			if !ok {
				return nil, fmt.Errorf("filesystem permission %s is invalid", key)
			}
			remotePaths := make([]string, 0, len(paths))
			for _, path := range paths {
				remotePath, err := pathMapper.Remote(path)
				if err != nil {
					return nil, fmt.Errorf("project filesystem permission %s: %w", key, err)
				}
				remotePaths = append(remotePaths, remotePath)
			}
			projected[key] = remotePaths
		case "globScanMaxDepth":
			projected[key] = value
		case "entries":
			if value == nil {
				projected[key] = nil
				continue
			}
			entries, ok := permissionEntries(value)
			if !ok {
				return nil, errors.New("filesystem permission entries are invalid")
			}
			remoteEntries := make([]map[string]any, 0, len(entries))
			for _, entry := range entries {
				remoteEntry, err := remotePermissionEntry(entry)
				if err != nil {
					return nil, err
				}
				remoteEntries = append(remoteEntries, remoteEntry)
			}
			projected[key] = remoteEntries
		default:
			return nil, fmt.Errorf("filesystem permission field %q is not allowed", key)
		}
	}
	return projected, nil
}

func remotePermissionEntry(entry map[string]any) (map[string]any, error) {
	access, ok := entry["access"].(string)
	if !ok {
		return nil, errors.New("filesystem permission entry access is invalid")
	}
	path, ok := entry["path"].(map[string]any)
	if !ok {
		return nil, errors.New("filesystem permission entry path is invalid")
	}
	remotePath := make(map[string]any, len(path))
	for key, value := range path {
		switch key {
		case "path":
			local, ok := value.(string)
			if !ok {
				return nil, errors.New("filesystem path entry is invalid")
			}
			projected, err := pathMapper.Remote(local)
			if err != nil {
				return nil, fmt.Errorf("project filesystem permission entry: %w", err)
			}
			remotePath[key] = projected
		case "pattern":
			local, ok := value.(string)
			if !ok {
				return nil, errors.New("filesystem glob pattern is invalid")
			}
			// A deny pattern is matched, never opened, so it projects through
			// the pattern mapper rather than the path mapper.
			projected, err := pathMapper.RemotePattern(local)
			if err != nil {
				return nil, fmt.Errorf("project filesystem glob pattern: %w", err)
			}
			remotePath[key] = projected
		case "type", "value":
			remotePath[key] = value
		default:
			return nil, fmt.Errorf("filesystem permission entry path field %q is not allowed", key)
		}
	}
	return map[string]any{"access": access, "path": remotePath}, nil
}

// permissionPaths and permissionEntries accept both the concrete slice types
// Guard.ValidatePermissions builds and the []any a JSON decode produces, because
// the Broker takes its permission validator as an interface and a caller may
// legitimately hand back the decoded profile.
func permissionPaths(value any) ([]string, bool) {
	if paths, ok := value.([]string); ok {
		return paths, true
	}
	raw, ok := value.([]any)
	if !ok {
		return nil, false
	}
	paths := make([]string, 0, len(raw))
	for _, item := range raw {
		path, ok := item.(string)
		if !ok {
			return nil, false
		}
		paths = append(paths, path)
	}
	return paths, true
}

func permissionEntries(value any) ([]map[string]any, bool) {
	if entries, ok := value.([]map[string]any); ok {
		return entries, true
	}
	raw, ok := value.([]any)
	if !ok {
		return nil, false
	}
	entries := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		entries = append(entries, entry)
	}
	return entries, true
}

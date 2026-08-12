package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	MaxPageSize          = 100
	MaxCWDFilter         = 32
	MaxTextItems         = 1
	MaxTextLength        = 200_000
	MaxOpaqueLength      = 512
	MaxSearchLength      = 512
	MaxPathLength        = 4_096
	MaxPermissionEntries = 100
	MaxGlobScanDepth     = 32
)

var allowedMethods = map[string]struct{}{
	"model/list":     {},
	"thread/start":   {},
	"thread/list":    {},
	"thread/read":    {},
	"thread/resume":  {},
	"turn/start":     {},
	"turn/steer":     {},
	"turn/interrupt": {},
}

var allowedEvents = map[string]struct{}{
	"thread/status/changed":   {},
	"thread/name/updated":     {},
	"turn/started":            {},
	"turn/completed":          {},
	"turn/plan/updated":       {},
	"item/agentMessage/delta": {},
	"error":                   {},
}

var deniedPrefixes = []string{
	"account/", "auth/", "command/", "config/", "environment/", "exec/", "fs/", "login/",
	"marketplace/", "mcpServer/", "memory/", "plugin/", "process/", "raw/", "remoteControl/",
	"rpc/", "shell/", "skills/", "thread/memory", "thread/realtime", "thread/settings",
	"thread/shellCommand", "windowsSandbox/",
}

var allowedParamFields = map[string]map[string]struct{}{
	"model/list":     fields("cursor", "limit"),
	"thread/start":   fields("cwd", "model"),
	"thread/list":    fields("cursor", "limit", "cwd", "searchTerm"),
	"thread/read":    fields("threadId", "includeTurns"),
	"thread/resume":  fields("threadId"),
	"turn/start":     fields("threadId", "clientUserMessageId", "input"),
	"turn/steer":     fields("threadId", "clientUserMessageId", "input", "expectedTurnId"),
	"turn/interrupt": fields("threadId", "turnId"),
}

func AllowedMethods() []string {
	return []string{
		"model/list", "thread/start", "thread/list", "thread/read",
		"thread/resume", "turn/start", "turn/steer", "turn/interrupt",
	}
}

func MethodAllowed(method string) bool {
	_, ok := allowedMethods[method]
	return ok
}

func EventAllowed(method string) bool {
	_, ok := allowedEvents[method]
	return ok
}

func DenialReason(method string) string {
	if MethodAllowed(method) {
		return ""
	}
	for _, prefix := range deniedPrefixes {
		if strings.HasPrefix(method, prefix) {
			return fmt.Sprintf("method family %s is explicitly denied", prefix)
		}
	}
	return "method is not present in the remote-control allowlist"
}

type Guard struct {
	roots      []string
	sandboxCap string
}

type DeniedError struct{ Err error }

func (e *DeniedError) Error() string { return e.Err.Error() }
func (e *DeniedError) Unwrap() error { return e.Err }

func Denied(message string) error { return &DeniedError{Err: errors.New(message)} }

func IsDenied(err error) bool {
	var denied *DeniedError
	return errors.As(err, &denied)
}

func NewGuard(roots []string, sandboxCap string) (*Guard, error) {
	if sandboxCap != "read-only" && sandboxCap != "workspace-write" {
		return nil, errors.New("invalid sandbox cap")
	}
	if len(roots) == 0 || len(roots) > MaxCWDFilter {
		return nil, fmt.Errorf("workspace roots must contain 1 to %d paths", MaxCWDFilter)
	}
	resolved := make([]string, 0, len(roots))
	seen := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		path, err := filepath.EvalSymlinks(filepath.Clean(root))
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(path) || utf8.RuneCountInString(path) > MaxPathLength {
			return nil, errors.New("workspace root is invalid")
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		resolved = append(resolved, path)
	}
	return &Guard{roots: resolved, sandboxCap: sandboxCap}, nil
}

func (g *Guard) WorkspaceRoots() []string {
	return append([]string(nil), g.roots...)
}

// Enforce clones and validates params before they are sent to app-server.
func (g *Guard) Enforce(method string, raw json.RawMessage) (result json.RawMessage, err error) {
	defer func() {
		if err != nil && !IsDenied(err) {
			err = &DeniedError{Err: err}
		}
	}()
	if reason := DenialReason(method); reason != "" {
		return nil, errors.New(reason)
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	supplied, err := decodeParams(raw)
	if err != nil {
		return nil, fmt.Errorf("params must be a JSON object: %w", err)
	}
	allowed := allowedParamFields[method]
	params := make(map[string]any, len(allowed)+3)
	for key, value := range supplied {
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("parameter %q is not allowed for %s", key, method)
		}
		params[key] = value
	}
	switch method {
	case "model/list":
		if err := validatePage(params); err != nil {
			return nil, err
		}
	case "thread/start":
		cwd, err := requiredString(params, "cwd", MaxPathLength)
		if err != nil {
			return nil, errors.New("thread/start requires an allowlisted cwd")
		}
		canonical, err := g.CanonicalCWD(cwd)
		if err != nil {
			return nil, err
		}
		params["cwd"] = canonical
		if err := validateOptionalString(params, "model", MaxOpaqueLength); err != nil {
			return nil, err
		}
		params["sandbox"] = g.sandboxCap
		params["approvalPolicy"] = "on-request"
		params["approvalsReviewer"] = "user"
	case "thread/resume":
		if _, err := requiredString(params, "threadId", MaxOpaqueLength); err != nil {
			return nil, err
		}
		params["sandbox"] = g.sandboxCap
		params["approvalPolicy"] = "on-request"
		params["approvalsReviewer"] = "user"
	case "thread/list":
		if err := validatePage(params); err != nil {
			return nil, err
		}
		cwd, err := g.threadListCWDs(params["cwd"])
		if err != nil {
			return nil, err
		}
		params["cwd"] = cwd
		if err := validateOptionalString(params, "searchTerm", MaxSearchLength); err != nil {
			return nil, err
		}
	case "thread/read":
		if _, err := requiredString(params, "threadId", MaxOpaqueLength); err != nil {
			return nil, err
		}
		if value, exists := params["includeTurns"]; exists && value != nil {
			if _, ok := value.(bool); !ok {
				return nil, errors.New("includeTurns must be a boolean")
			}
		} else {
			params["includeTurns"] = false
		}
	case "turn/start":
		if _, err := requiredString(params, "threadId", MaxOpaqueLength); err != nil {
			return nil, err
		}
		if err := validateOptionalString(params, "clientUserMessageId", MaxOpaqueLength); err != nil {
			return nil, err
		}
		input, err := textOnlyInput(params["input"])
		if err != nil {
			return nil, err
		}
		params["input"] = input
		params["sandboxPolicy"] = g.turnSandboxPolicy()
		params["approvalPolicy"] = "on-request"
		params["approvalsReviewer"] = "user"
	case "turn/steer":
		if _, err := requiredString(params, "threadId", MaxOpaqueLength); err != nil {
			return nil, err
		}
		if _, err := requiredString(params, "expectedTurnId", MaxOpaqueLength); err != nil {
			return nil, err
		}
		if err := validateOptionalString(params, "clientUserMessageId", MaxOpaqueLength); err != nil {
			return nil, err
		}
		input, err := textOnlyInput(params["input"])
		if err != nil {
			return nil, err
		}
		params["input"] = input
	case "turn/interrupt":
		if _, err := requiredString(params, "threadId", MaxOpaqueLength); err != nil {
			return nil, err
		}
		if _, err := requiredString(params, "turnId", MaxOpaqueLength); err != nil {
			return nil, err
		}
	}
	encodedSize, err := ensureASCIIJSONSize(params)
	if err != nil {
		return nil, err
	}
	if encodedSize > MaxEnsureASCIIParamsBytes {
		return nil, fmt.Errorf("RPC params exceed the %d-byte ensure_ascii budget", MaxEnsureASCIIParamsBytes)
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxEnsureASCIIParamsBytes {
		return nil, fmt.Errorf("RPC params exceed the %d-byte Go JSON budget", MaxEnsureASCIIParamsBytes)
	}
	return encoded, nil
}

func (g *Guard) threadListCWDs(value any) ([]string, error) {
	if value == nil {
		return append([]string(nil), g.roots...), nil
	}
	var candidates []any
	switch typed := value.(type) {
	case string:
		candidates = []any{typed}
	case []any:
		candidates = typed
	default:
		return nil, fmt.Errorf("thread/list cwd must contain 1 to %d paths", MaxCWDFilter)
	}
	if len(candidates) == 0 || len(candidates) > MaxCWDFilter {
		return nil, fmt.Errorf("thread/list cwd must contain 1 to %d paths", MaxCWDFilter)
	}
	projected := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		cwd, ok := candidate.(string)
		if !ok || cwd == "" || utf8.RuneCountInString(cwd) > MaxPathLength {
			return nil, errors.New("thread/list cwd contains an invalid path")
		}
		canonical, err := g.CanonicalCWD(cwd)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		projected = append(projected, canonical)
	}
	return projected, nil
}

func (g *Guard) CanonicalCWD(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("cwd must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("cwd is not a directory")
	}
	for _, root := range g.roots {
		relative, err := filepath.Rel(root, resolved)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("cwd %q is outside the configured workspace roots", path)
}

func (g *Guard) ContainsCWD(path string) bool {
	_, err := g.CanonicalCWD(path)
	return err == nil
}

// ValidatePermissions permits only additional filesystem access already inside
// the configured roots and never grants network access.
func (g *Guard) ValidatePermissions(profile map[string]any) (map[string]any, error) {
	result := make(map[string]any)
	for key := range profile {
		if key != "fileSystem" && key != "network" {
			return nil, fmt.Errorf("permission field %q is not allowed", key)
		}
	}
	if network, exists := profile["network"]; exists && network != nil {
		object, ok := network.(map[string]any)
		if !ok {
			return nil, errors.New("network permissions are invalid")
		}
		for key := range object {
			if key != "enabled" {
				return nil, fmt.Errorf("network permission field %q is not allowed", key)
			}
		}
		if enabled, _ := object["enabled"].(bool); enabled {
			return nil, errors.New("remote approvals cannot enable network access")
		}
		result["network"] = map[string]any{"enabled": false}
	}
	if fileSystem, exists := profile["fileSystem"]; exists && fileSystem != nil {
		object, ok := fileSystem.(map[string]any)
		if !ok {
			return nil, errors.New("filesystem permissions are invalid")
		}
		projected := make(map[string]any)
		for key, value := range object {
			if key != "read" && key != "write" && key != "entries" && key != "globScanMaxDepth" {
				return nil, fmt.Errorf("filesystem permission field %q is not allowed", key)
			}
			if key == "globScanMaxDepth" {
				if value == nil {
					projected[key] = nil
					continue
				}
				depth, ok := value.(float64)
				if !ok || depth < 1 || depth > MaxGlobScanDepth || depth != float64(int(depth)) {
					return nil, fmt.Errorf("globScanMaxDepth must be an integer between 1 and %d", MaxGlobScanDepth)
				}
				projected[key] = int(depth)
				continue
			}
			if key == "entries" {
				entries, err := g.validatePermissionEntries(value)
				if err != nil {
					return nil, err
				}
				projected[key] = entries
				continue
			}
			if key == "write" && g.sandboxCap == "read-only" {
				return nil, errors.New("read-only sandbox cap forbids filesystem write permissions")
			}
			if value == nil {
				projected[key] = nil
				continue
			}
			paths, ok := value.([]any)
			if !ok || len(paths) > MaxPermissionEntries {
				return nil, fmt.Errorf("filesystem permission %s must be an array", key)
			}
			canonical := make([]string, 0, len(paths))
			for _, rawPath := range paths {
				path, ok := rawPath.(string)
				if !ok {
					return nil, fmt.Errorf("filesystem permission %s contains a non-string path", key)
				}
				resolved, err := g.canonicalExistingPath(path)
				if err != nil {
					return nil, err
				}
				canonical = append(canonical, resolved)
			}
			projected[key] = canonical
		}
		result["fileSystem"] = projected
	}
	return result, nil
}

func (g *Guard) validatePermissionEntries(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	entries, ok := value.([]any)
	if !ok || len(entries) > MaxPermissionEntries {
		return nil, errors.New("filesystem permission entries must be an array")
	}
	projected := make([]map[string]any, 0, len(entries))
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]any)
		if !ok || len(entry) != 2 {
			return nil, errors.New("filesystem permission entry is invalid")
		}
		access, ok := entry["access"].(string)
		if !ok || (access != "read" && access != "write" && access != "deny") {
			return nil, errors.New("filesystem permission entry access is invalid")
		}
		if access == "write" && g.sandboxCap == "read-only" {
			return nil, errors.New("read-only sandbox cap forbids filesystem write permissions")
		}
		path, ok := entry["path"].(map[string]any)
		if !ok {
			return nil, errors.New("filesystem permission entry path is invalid")
		}
		projectedPath, err := g.validatePermissionEntryPath(path, access)
		if err != nil {
			return nil, err
		}
		projected = append(projected, map[string]any{"access": access, "path": projectedPath})
	}
	return projected, nil
}

func (g *Guard) validatePermissionEntryPath(path map[string]any, access string) (map[string]any, error) {
	kind, ok := path["type"].(string)
	if !ok {
		return nil, errors.New("filesystem permission entry path type is invalid")
	}
	switch kind {
	case "path":
		if len(path) != 2 {
			return nil, errors.New("filesystem path entry contains unsupported fields")
		}
		value, ok := path["path"].(string)
		if !ok {
			return nil, errors.New("filesystem path entry is invalid")
		}
		var canonical string
		var err error
		if access == "read" {
			canonical, err = g.canonicalExistingPath(value)
		} else {
			canonical, err = g.canonicalProspectivePath(value)
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "path", "path": canonical}, nil
	case "glob_pattern":
		if len(path) != 2 {
			return nil, errors.New("filesystem glob entry contains unsupported fields")
		}
		pattern, ok := path["pattern"].(string)
		if !ok || pattern == "" || utf8.RuneCountInString(pattern) > MaxPathLength {
			return nil, errors.New("filesystem glob pattern is invalid")
		}
		for _, part := range strings.Split(filepath.Clean(pattern), string(filepath.Separator)) {
			if part == ".." {
				return nil, errors.New("filesystem glob pattern cannot contain parent traversal")
			}
		}
		if access != "deny" {
			return nil, errors.New("filesystem glob patterns may only deny access")
		}
		if _, err := g.canonicalGlobRoot(pattern, false); err != nil {
			return nil, err
		}
		return map[string]any{"type": "glob_pattern", "pattern": pattern}, nil
	case "special":
		if len(path) != 2 {
			return nil, errors.New("filesystem special entry contains unsupported fields")
		}
		value, ok := path["value"].(map[string]any)
		if !ok || value["kind"] != "project_roots" {
			return nil, errors.New("only project_roots special filesystem entries are allowed")
		}
		if len(value) > 2 {
			return nil, errors.New("project_roots entry contains unsupported fields")
		}
		for key := range value {
			if key != "kind" && key != "subpath" {
				return nil, errors.New("project_roots entry contains unsupported fields")
			}
		}
		subpath, subpathOK := value["subpath"].(string)
		if value["subpath"] != nil {
			if !subpathOK || subpath == "" || filepath.IsAbs(subpath) || filepath.Clean(subpath) == "." || filepath.Clean(subpath) == ".." || strings.HasPrefix(filepath.Clean(subpath), ".."+string(filepath.Separator)) {
				return nil, errors.New("project_roots subpath is invalid")
			}
			for _, root := range g.roots {
				candidate := filepath.Join(root, subpath)
				if access == "read" {
					if _, err := g.canonicalExistingPath(candidate); err != nil {
						return nil, err
					}
				} else if _, err := g.canonicalProspectivePath(candidate); err != nil {
					return nil, err
				}
			}
		}
		return map[string]any{"type": "special", "value": map[string]any{"kind": "project_roots", "subpath": value["subpath"]}}, nil
	default:
		return nil, fmt.Errorf("filesystem permission path type %q is not allowed", kind)
	}
}

func (g *Guard) canonicalGlobRoot(pattern string, requireExisting bool) (string, error) {
	if !filepath.IsAbs(pattern) {
		return "", errors.New("filesystem glob pattern must be absolute")
	}
	separator := string(filepath.Separator)
	parts := strings.Split(filepath.Clean(pattern), separator)
	literal := separator
	for _, part := range parts {
		if part == "" {
			continue
		}
		if strings.ContainsAny(part, "*?[") {
			break
		}
		literal = filepath.Join(literal, part)
	}
	if literal == separator {
		return "", errors.New("filesystem glob pattern has no workspace-rooted literal prefix")
	}
	if requireExisting {
		return g.canonicalExistingPath(literal)
	}
	return g.canonicalProspectivePath(literal)
}

func (g *Guard) ValidateApprovalDetails(kind string, details map[string]any) error {
	if cwd, exists := details["cwd"]; exists && cwd != nil {
		path, ok := cwd.(string)
		if !ok {
			return errors.New("approval cwd is invalid")
		}
		if _, err := g.CanonicalCWD(path); err != nil {
			return err
		}
	}
	switch kind {
	case "command":
		for _, key := range []string{
			"networkApprovalContext", "proposedNetworkPolicyAmendments", "proposedExecpolicyAmendment", "environmentId",
		} {
			if value, exists := details[key]; exists && value != nil {
				if values, ok := value.([]any); !ok || len(values) != 0 {
					return fmt.Errorf("command approval requests forbidden capability %s", key)
				}
			}
		}
		if additional, exists := details["additionalPermissions"]; exists && additional != nil {
			profile, ok := additional.(map[string]any)
			if !ok {
				return errors.New("additional command permissions are invalid")
			}
			if _, err := g.ValidatePermissions(profile); err != nil {
				return err
			}
		}
	case "file_change":
		if g.sandboxCap == "read-only" {
			return errors.New("read-only sandbox cap forbids file change approvals")
		}
		if grantRoot, exists := details["grantRoot"]; exists && grantRoot != nil {
			path, ok := grantRoot.(string)
			if !ok {
				return errors.New("file approval grantRoot is invalid")
			}
			if _, err := g.CanonicalCWD(path); err != nil {
				return err
			}
		}
		if changes, exists := details["fileChanges"]; exists && changes != nil {
			objects, ok := changes.(map[string]any)
			if !ok || len(objects) > 100 {
				return errors.New("fileChanges is invalid")
			}
			for path, rawChange := range objects {
				if _, err := g.canonicalProspectivePath(path); err != nil {
					return err
				}
				change, _ := rawChange.(map[string]any)
				if movePath, exists := change["move_path"]; exists && movePath != nil {
					target, ok := movePath.(string)
					if !ok {
						return errors.New("file change move_path is invalid")
					}
					if _, err := g.canonicalProspectivePath(target); err != nil {
						return err
					}
				}
			}
		}
	case "permission":
		return nil
	default:
		return errors.New("unknown approval kind")
	}
	return nil
}

func (g *Guard) canonicalExistingPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("permission path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve permission path: %w", err)
	}
	if _, err := os.Stat(resolved); err != nil {
		return "", fmt.Errorf("stat permission path: %w", err)
	}
	for _, root := range g.roots {
		relative, err := filepath.Rel(root, resolved)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("permission path %q is outside configured workspace roots", path)
}

func (g *Guard) canonicalProspectivePath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("file change path must be absolute")
	}
	current := filepath.Clean(path)
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			for _, root := range g.roots {
				relative, relErr := filepath.Rel(root, resolved)
				if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
					return resolved, nil
				}
			}
			return "", fmt.Errorf("file change path %q is outside configured workspace roots", path)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("resolve file change path: %w", err)
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func (g *Guard) turnSandboxPolicy() map[string]any {
	if g.sandboxCap == "read-only" {
		return map[string]any{"type": "readOnly", "networkAccess": false}
	}
	return map[string]any{
		"type": "workspaceWrite", "writableRoots": []string{}, "networkAccess": false,
		"excludeSlashTmp": true, "excludeTmpdirEnvVar": true,
	}
}

func textOnlyInput(value any) ([]map[string]any, error) {
	items, ok := value.([]any)
	if !ok || len(items) != MaxTextItems {
		return nil, fmt.Errorf("remote turns require exactly %d text input", MaxTextItems)
	}
	object, ok := items[0].(map[string]any)
	if !ok || (len(object) != 2 && len(object) != 3) || object["type"] != "text" {
		return nil, errors.New("remote turn input only supports text with optional empty text_elements")
	}
	for key := range object {
		if key != "type" && key != "text" && key != "text_elements" {
			return nil, errors.New("remote turn input only supports text with optional empty text_elements")
		}
	}
	if textElements, exists := object["text_elements"]; exists {
		elements, ok := textElements.([]any)
		if !ok || len(elements) != 0 {
			return nil, errors.New("remote turn input text_elements must be empty")
		}
	}
	text, ok := object["text"].(string)
	if !ok || strings.TrimSpace(text) == "" || utf8.RuneCountInString(text) > MaxTextLength {
		return nil, fmt.Errorf("turn text must contain 1 to %d characters", MaxTextLength)
	}
	if ensureASCIIStringContentSize(text) > MaxEnsureASCIITextBytes {
		return nil, fmt.Errorf("turn text exceeds the %d-byte ensure_ascii budget", MaxEnsureASCIITextBytes)
	}
	return []map[string]any{{"type": "text", "text": text, "text_elements": []any{}}}, nil
}

func decodeParams(raw json.RawMessage) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var params map[string]any
	if err := decoder.Decode(&params); err != nil {
		return nil, err
	}
	if params == nil {
		return nil, errors.New("params must be an object")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("params contain trailing JSON")
		}
		return nil, err
	}
	return params, nil
}

func validatePage(params map[string]any) error {
	if err := validateOptionalString(params, "cursor", MaxOpaqueLength); err != nil {
		return err
	}
	value, exists := params["limit"]
	if !exists || value == nil {
		delete(params, "limit")
		return nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return fmt.Errorf("limit must be an integer between 1 and %d", MaxPageSize)
	}
	limit, err := number.Int64()
	if err != nil || limit < 1 || limit > MaxPageSize {
		return fmt.Errorf("limit must be an integer between 1 and %d", MaxPageSize)
	}
	params["limit"] = limit
	return nil
}

func requiredString(params map[string]any, field string, maximum int) (string, error) {
	value, ok := params[field].(string)
	if !ok || value == "" || utf8.RuneCountInString(value) > maximum {
		return "", fmt.Errorf("%s must be a non-empty string of at most %d characters", field, maximum)
	}
	return value, nil
}

func validateOptionalString(params map[string]any, field string, maximum int) error {
	value, exists := params[field]
	if !exists || value == nil {
		delete(params, field)
		return nil
	}
	if _, err := requiredString(params, field, maximum); err != nil {
		return err
	}
	return nil
}

func fields(names ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(names))
	for _, name := range names {
		result[name] = struct{}{}
	}
	return result
}

package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/appserver"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/wspath"
)

var pathMapper = wspath.NewMapper()

const (
	maxApprovalRequestBytes = 256 << 10
	maxApprovalPayloadBytes = 60 << 10
	maxApprovalJSONDepth    = 16
	maxApprovalFields       = 64
)

type EmitFunc func(context.Context, string, any) error

type decision struct {
	approve bool
	epoch   string
}

type pendingApproval struct {
	epoch              string
	expiresAt          time.Time
	result             chan decision
	grantedPermissions map[string]any
	commandDecisions   commandDecisionOptions
}

type commandDecisionOptions struct {
	constrained bool
	accept      bool
	decline     bool
	cancel      bool
}

type Broker struct {
	mu                  sync.Mutex
	epoch               string
	connected           bool
	timeout             time.Duration
	emit                EmitFunc
	now                 func() time.Time
	pending             map[string]*pendingApproval
	validateRequest     func(string, map[string]any) error
	validatePermissions func(map[string]any) (map[string]any, error)
}

func (b *Broker) SetValidators(
	requestValidator func(string, map[string]any) error,
	permissionValidator func(map[string]any) (map[string]any, error),
) {
	b.mu.Lock()
	b.validateRequest = requestValidator
	b.validatePermissions = permissionValidator
	b.mu.Unlock()
}

func New(timeout time.Duration, emit EmitFunc) *Broker {
	if timeout <= 0 || timeout > 120*time.Second {
		timeout = 120 * time.Second
	}
	return &Broker{timeout: timeout, emit: emit, now: time.Now, pending: make(map[string]*pendingApproval)}
}

func (b *Broker) SetEpoch(epoch string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if epoch == b.epoch {
		return
	}
	b.cancelPendingLocked()
	b.epoch = epoch
}

func (b *Broker) SetConnected(connected bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.connected == connected {
		return
	}
	b.connected = connected
	if !connected {
		b.cancelPendingLocked()
	}
}

func (b *Broker) cancelPendingLocked() {
	for id, pending := range b.pending {
		select {
		case pending.result <- decision{approve: false, epoch: pending.epoch}:
		default:
		}
		delete(b.pending, id)
	}
}

func (b *Broker) Request(ctx context.Context, method string, params json.RawMessage) (any, *appserver.RPCError) {
	kind, ok := approvalKind(method)
	if !ok {
		return nil, &appserver.RPCError{Code: -32601, Message: "app-server request is not in the approval allowlist"}
	}
	if len(params) == 0 || len(params) > maxApprovalRequestBytes {
		return deniedResultBeforeDecisionOptions(method, "approval params exceed the size limit")
	}
	if err := validateJSONDepth(params, maxApprovalJSONDepth); err != nil {
		return deniedResultBeforeDecisionOptions(method, "approval params exceed the nesting limit")
	}
	details := make(map[string]any)
	if err := json.Unmarshal(params, &details); err != nil {
		return deniedResultBeforeDecisionOptions(method, "approval params are invalid")
	}
	if len(details) == 0 || len(details) > maxApprovalFields {
		return deniedResultBeforeDecisionOptions(method, "approval params have an invalid field count")
	}
	commandDecisions, err := parseCommandDecisionOptions(method, details)
	if err != nil {
		return commandDecisionError("availableDecisions is invalid")
	}
	deny := func(reason string) (any, *appserver.RPCError) {
		return deniedResultWithOptions(method, reason, commandDecisions)
	}
	b.mu.Lock()
	epoch := b.epoch
	connected := b.connected
	requestValidator := b.validateRequest
	permissionValidator := b.validatePermissions
	b.mu.Unlock()
	if len(epoch) < 16 {
		return deny("app-server epoch is unavailable")
	}
	if !connected {
		return deny("device control channel is disconnected")
	}
	id, err := protocol.NewID()
	if err != nil {
		return deny("cannot create approval id")
	}
	if requestValidator != nil {
		if err := requestValidator(kind, details); err != nil {
			return deny(err.Error())
		}
	}
	var grantedPermissions map[string]any
	if kind == "permission" {
		if permissionValidator == nil {
			return deny("permission approval is not configured")
		}
		permissions, ok := details["permissions"].(map[string]any)
		if !ok {
			return deny("permission request is invalid")
		}
		grantedPermissions, err = permissionValidator(permissions)
		if err != nil {
			return deny(err.Error())
		}
	}
	projectedDetails, err := projectApprovalDetails(kind, details, grantedPermissions)
	if err != nil {
		return deny("approval request exceeds the remote-control contract")
	}
	now := b.now().UTC()
	expiresAt := now.Add(b.timeout)
	pending := &pendingApproval{
		epoch: epoch, expiresAt: expiresAt, result: make(chan decision, 1),
		grantedPermissions: grantedPermissions, commandDecisions: commandDecisions,
	}
	request := protocol.ApprovalRequestPayload{
		ApprovalID: id,
		CommandID:  extractString(details, "command_id", "commandId", "turnId", "turn_id"),
		Kind:       kind,
		Summary:    approvalSummary(kind, details),
		Details:    projectedDetails,
		ExpiresAt:  expiresAt,
	}
	if request.CommandID == "" || utf8.RuneCountInString(request.CommandID) > 255 {
		request.CommandID = "appserver:" + id
	}
	encodedRequest, err := json.Marshal(request)
	if err != nil || len(encodedRequest) > maxApprovalPayloadBytes {
		return deny("approval request exceeds the remote-control payload limit")
	}
	b.mu.Lock()
	if b.epoch != epoch || !b.connected {
		b.mu.Unlock()
		return deny("device control channel disconnected before approval delivery")
	}
	b.pending[id] = pending
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, id)
		b.mu.Unlock()
	}()
	if b.emit == nil || b.emit(ctx, protocol.TypeApprovalRequest, request) != nil {
		return deny("approval request could not be delivered")
	}
	timer := time.NewTimer(time.Until(expiresAt))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return deny("approval request was cancelled")
	case <-timer.C:
		return deny("approval request timed out")
	case result := <-pending.result:
		if !result.approve || result.epoch != epoch {
			return deny("approval request was denied")
		}
		return approvedResultWithOptions(method, pending.grantedPermissions, pending.commandDecisions)
	}
}

func (b *Broker) Resolve(epoch string, payload protocol.ApprovalDecisionPayload) error {
	if payload.Decision != "approve" && payload.Decision != "deny" {
		return errors.New("approval decision must be approve or deny")
	}
	if payload.DecidedAt.IsZero() {
		return errors.New("approval decision timestamp is required")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if epoch != b.epoch {
		return errors.New("approval belongs to a stale app-server epoch")
	}
	pending := b.pending[payload.ApprovalID]
	if pending == nil {
		return errors.New("approval is unknown or already resolved")
	}
	if !b.now().Before(pending.expiresAt) {
		return errors.New("approval has expired")
	}
	if payload.DecidedAt.After(pending.expiresAt) || payload.DecidedAt.Before(pending.expiresAt.Add(-b.timeout-time.Minute)) {
		return errors.New("approval decision timestamp is outside the request window")
	}
	select {
	case pending.result <- decision{approve: payload.Decision == "approve", epoch: epoch}:
		return nil
	default:
		return errors.New("approval is already resolved")
	}
}

func approvalKind(method string) (string, bool) {
	switch method {
	case "item/commandExecution/requestApproval", "execCommandApproval":
		return "command", true
	case "item/fileChange/requestApproval", "applyPatchApproval":
		return "file_change", true
	case "item/permissions/requestApproval":
		return "permission", true
	default:
		return "", false
	}
}

func approvedResult(method string, permissions map[string]any) (any, *appserver.RPCError) {
	return approvedResultWithOptions(method, permissions, commandDecisionOptions{})
}

func approvedResultWithOptions(method string, permissions map[string]any, options commandDecisionOptions) (any, *appserver.RPCError) {
	switch method {
	case "item/commandExecution/requestApproval":
		if options.constrained && !options.accept {
			return commandDecisionError("remote approval requires accept")
		}
		return map[string]string{"decision": "accept"}, nil
	case "item/fileChange/requestApproval":
		return map[string]string{"decision": "accept"}, nil
	case "execCommandApproval", "applyPatchApproval":
		return map[string]string{"decision": "approved"}, nil
	case "item/permissions/requestApproval":
		return map[string]any{"permissions": permissions, "scope": "turn", "strictAutoReview": true}, nil
	default:
		return nil, &appserver.RPCError{Code: -32601, Message: "approval method is not supported"}
	}
}

func deniedResult(method, reason string) (any, *appserver.RPCError) {
	return deniedResultWithOptions(method, reason, commandDecisionOptions{})
}

func deniedResultBeforeDecisionOptions(method, reason string) (any, *appserver.RPCError) {
	if method == "item/commandExecution/requestApproval" {
		return commandDecisionError(reason)
	}
	return deniedResult(method, reason)
}

func deniedResultWithOptions(method, reason string, options commandDecisionOptions) (any, *appserver.RPCError) {
	switch method {
	case "item/commandExecution/requestApproval":
		if options.constrained {
			if options.decline {
				return map[string]string{"decision": "decline"}, nil
			}
			if options.cancel {
				return map[string]string{"decision": "cancel"}, nil
			}
			return commandDecisionError("no supported denial decision is available")
		}
		return map[string]string{"decision": "decline"}, nil
	case "item/fileChange/requestApproval":
		return map[string]string{"decision": "decline"}, nil
	case "execCommandApproval", "applyPatchApproval":
		return map[string]any{
			"decision": map[string]any{
				"denied": map[string]string{"rejection": reason},
			},
		}, nil
	case "item/permissions/requestApproval":
		return nil, &appserver.RPCError{Code: -32001, Message: "permission request denied: " + reason}
	default:
		return nil, &appserver.RPCError{Code: -32601, Message: "approval method is not supported"}
	}
}

func parseCommandDecisionOptions(method string, details map[string]any) (commandDecisionOptions, error) {
	if method != "item/commandExecution/requestApproval" {
		return commandDecisionOptions{}, nil
	}
	raw, exists := details["availableDecisions"]
	if !exists || raw == nil {
		return commandDecisionOptions{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return commandDecisionOptions{}, errors.New("availableDecisions must be an array or null")
	}
	options := commandDecisionOptions{constrained: true}
	for _, value := range values {
		text, isString := value.(string)
		if !isString {
			if _, isObject := value.(map[string]any); isObject {
				continue
			}
			return commandDecisionOptions{}, errors.New("availableDecisions contains an invalid value")
		}
		switch text {
		case "accept":
			options.accept = true
		case "decline":
			options.decline = true
		case "cancel":
			options.cancel = true
		case "acceptForSession":
		default:
			return commandDecisionOptions{}, fmt.Errorf("unsupported available decision %q", text)
		}
	}
	return options, nil
}

func commandDecisionError(reason string) (any, *appserver.RPCError) {
	return nil, &appserver.RPCError{
		Code: -32001, Message: "command approval cannot return a permitted decision: " + reason,
	}
}

func extractString(details map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := details[key].(string); ok {
			return value
		}
	}
	return ""
}

func approvalSummary(kind string, details map[string]any) string {
	if reason := extractString(details, "reason", "command", "path"); reason != "" {
		return fmt.Sprintf("%s approval: %s", kind, truncateRunes(reason, 240))
	}
	return kind + " approval requested by Codex"
}

func projectApprovalDetails(kind string, details, permissions map[string]any) (map[string]any, error) {
	projected := make(map[string]any)
	for _, field := range []string{"threadId", "thread_id", "turnId", "turn_id", "itemId", "item_id", "approvalId", "commandId", "command_id", "conversationId"} {
		if value, exists := details[field]; exists && value != nil {
			text, ok := value.(string)
			if !ok || text == "" || utf8.RuneCountInString(text) > 512 {
				return nil, fmt.Errorf("approval field %s is invalid", field)
			}
			projected[field] = text
		}
	}
	for _, field := range []string{"cwd", "grantRoot", "path"} {
		if value, exists := details[field]; exists && value != nil {
			text, ok := value.(string)
			if !ok || text == "" || utf8.RuneCountInString(text) > 4_096 {
				return nil, fmt.Errorf("approval path field %s is invalid", field)
			}
			remote, err := pathMapper.Remote(text)
			if err != nil {
				return nil, fmt.Errorf("project approval path field %s: %w", field, err)
			}
			projected[field] = remote
		}
	}
	if reason := extractString(details, "reason"); reason != "" {
		projected["reason"] = truncateRunes(reason, 4_096)
	}
	if startedAt, ok := details["startedAtMs"].(float64); ok {
		projected["startedAtMs"] = startedAt
	}
	switch kind {
	case "command":
		if command, exists := details["command"]; exists && command != nil {
			switch typed := command.(type) {
			case string:
				if typed == "" {
					return nil, errors.New("approval command is empty")
				}
				projected["command"] = truncateRunes(typed, 16_384)
			case []any:
				if len(typed) == 0 || len(typed) > 128 {
					return nil, errors.New("approval command array is invalid")
				}
				parts := make([]string, 0, len(typed))
				for _, rawPart := range typed {
					part, ok := rawPart.(string)
					if !ok || part == "" {
						return nil, errors.New("approval command contains an invalid part")
					}
					parts = append(parts, truncateRunes(part, 4_096))
				}
				projected["command"] = parts
			default:
				return nil, errors.New("approval command is invalid")
			}
		}
	case "file_change":
		if rawChanges, exists := details["fileChanges"]; exists && rawChanges != nil {
			changes, ok := rawChanges.(map[string]any)
			if !ok || len(changes) == 0 || len(changes) > 100 {
				return nil, errors.New("file changes are invalid")
			}
			projectedChanges := make(map[string]any, len(changes))
			for path, rawChange := range changes {
				if path == "" || utf8.RuneCountInString(path) > 4_096 {
					return nil, errors.New("file change path is invalid")
				}
				change, ok := rawChange.(map[string]any)
				if !ok {
					return nil, errors.New("file change operation is invalid")
				}
				typeName, ok := change["type"].(string)
				if !ok || (typeName != "add" && typeName != "delete" && typeName != "update") {
					return nil, errors.New("file change type is invalid")
				}
				projectedChange := map[string]any{"type": typeName}
				if movePath, exists := change["move_path"]; exists && movePath != nil {
					target, ok := movePath.(string)
					if !ok || target == "" || utf8.RuneCountInString(target) > 4_096 {
						return nil, errors.New("file change move path is invalid")
					}
					remoteTarget, err := pathMapper.Remote(target)
					if err != nil {
						return nil, fmt.Errorf("project file change move path: %w", err)
					}
					projectedChange["move_path"] = remoteTarget
				}
				// The map is keyed by the changed file, so the key is a path and
				// projects like every other one. projectedChanges is a fresh map,
				// so rewriting the key cannot disturb what app-server receives.
				remotePath, err := pathMapper.Remote(path)
				if err != nil {
					return nil, fmt.Errorf("project file change path: %w", err)
				}
				projectedChanges[remotePath] = projectedChange
			}
			// Raw contents and unified diffs stay local. Paths and operation kinds
			// are the minimum context required for an informed remote decision.
			projected["fileChanges"] = projectedChanges
		}
	case "permission":
		if permissions == nil {
			return nil, errors.New("validated permissions are unavailable")
		}
		// The validated profile is the instance handed back to app-server, so it
		// is projected into a deep copy rather than in place.
		remotePermissions, err := policy.RemotePermissions(permissions)
		if err != nil {
			return nil, err
		}
		projected["permissions"] = remotePermissions
	default:
		return nil, errors.New("unknown approval kind")
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return nil, err
	}
	if len(encoded) > 64<<10 {
		return nil, errors.New("approval details exceed 64 KiB")
	}
	return projected, nil
}

func truncateRunes(value string, maximum int) string {
	if utf8.RuneCountInString(value) <= maximum {
		return value
	}
	runes := []rune(value)
	return string(runes[:maximum])
}

func validateJSONDepth(raw []byte, maximum int) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			continue
		}
		switch delimiter {
		case '{', '[':
			depth++
			if depth > maximum {
				return errors.New("approval JSON is too deeply nested")
			}
		case '}', ']':
			depth--
		}
	}
}

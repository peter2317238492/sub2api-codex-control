package appserver

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	frozenV2ContractURL   = "https://contracts.sub2api.invalid/codex/0.147.0/app-server-v2.json"
	responseContractURL   = "https://contracts.sub2api.invalid/codex/0.147.0/jsonrpc-response.json"
	errorContractURL      = "https://contracts.sub2api.invalid/codex/0.147.0/jsonrpc-error.json"
	serverRequestURL      = "https://contracts.sub2api.invalid/codex/0.147.0/server-request.json"
	initializeContractURL = "https://contracts.sub2api.invalid/codex/0.147.0/initialize-response.json"
)

//go:embed contracts/codex_app_server_protocol.v2.schemas.json
var frozenV2ContractBundle []byte

//go:embed contracts/JSONRPCResponse.json
var responseContractBundle []byte

//go:embed contracts/JSONRPCError.json
var errorContractBundle []byte

//go:embed contracts/ServerRequest.json
var serverRequestContractBundle []byte

//go:embed contracts/CommandExecutionRequestApprovalResponse.json
var commandApprovalResponseContractBundle []byte

//go:embed contracts/FileChangeRequestApprovalResponse.json
var fileChangeApprovalResponseContractBundle []byte

//go:embed contracts/PermissionsRequestApprovalResponse.json
var permissionsApprovalResponseContractBundle []byte

//go:embed contracts/ApplyPatchApprovalResponse.json
var applyPatchApprovalResponseContractBundle []byte

//go:embed contracts/ExecCommandApprovalResponse.json
var execCommandApprovalResponseContractBundle []byte

//go:embed contracts/v1/InitializeResponse.json
var initializeContractBundle []byte

var ErrContractViolation = errors.New("app-server message violates the frozen Codex contract")

type contractValidator struct {
	response      *jsonschema.Schema
	errorResponse *jsonschema.Schema
	notification  *jsonschema.Schema
	results       map[string]*jsonschema.Schema
	serverRequest *jsonschema.Schema
	serverResults map[string]*jsonschema.Schema
}

var (
	contractOnce      sync.Once
	frozenContract    *contractValidator
	frozenContractErr error
)

func loadFrozenContract() (*contractValidator, error) {
	contractOnce.Do(func() {
		frozenContract, frozenContractErr = compileFrozenContract()
	})
	return frozenContract, frozenContractErr
}

func compileFrozenContract() (*contractValidator, error) {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft7)
	resources := map[string][]byte{
		frozenV2ContractURL: frozenV2ContractBundle, responseContractURL: responseContractBundle,
		errorContractURL: errorContractBundle, serverRequestURL: serverRequestContractBundle,
		initializeContractURL: initializeContractBundle,
	}
	serverResultBundles := map[string][]byte{
		"item/commandExecution/requestApproval": commandApprovalResponseContractBundle,
		"item/fileChange/requestApproval":       fileChangeApprovalResponseContractBundle,
		"item/permissions/requestApproval":      permissionsApprovalResponseContractBundle,
		"applyPatchApproval":                    applyPatchApprovalResponseContractBundle,
		"execCommandApproval":                   execCommandApprovalResponseContractBundle,
	}
	serverResultURLs := make(map[string]string, len(serverResultBundles))
	for method, raw := range serverResultBundles {
		url := fmt.Sprintf("https://contracts.sub2api.invalid/codex/0.147.0/server-result/%s.json", method)
		resources[url] = raw
		serverResultURLs[method] = url
	}
	for url, raw := range resources {
		bundle, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("decode frozen app-server contract: %w", err)
		}
		if err := compiler.AddResource(url, bundle); err != nil {
			return nil, fmt.Errorf("load frozen app-server contract: %w", err)
		}
	}
	compile := func(location string) (*jsonschema.Schema, error) {
		schema, err := compiler.Compile(location)
		if err != nil {
			return nil, fmt.Errorf("compile frozen app-server contract: %w", err)
		}
		return schema, nil
	}

	responseSchema, err := compile(responseContractURL)
	if err != nil {
		return nil, err
	}
	errorSchema, err := compile(errorContractURL)
	if err != nil {
		return nil, err
	}
	notificationSchema, err := compile(frozenV2ContractURL + "#/definitions/ServerNotification")
	if err != nil {
		return nil, err
	}
	serverRequestSchema, err := compile(serverRequestURL)
	if err != nil {
		return nil, err
	}

	resultPointers := map[string]string{
		"initialize":     initializeContractURL,
		"model/list":     frozenV2ContractURL + "#/definitions/ModelListResponse",
		"thread/start":   frozenV2ContractURL + "#/definitions/ThreadStartResponse",
		"thread/list":    frozenV2ContractURL + "#/definitions/ThreadListResponse",
		"thread/read":    frozenV2ContractURL + "#/definitions/ThreadReadResponse",
		"thread/resume":  frozenV2ContractURL + "#/definitions/ThreadResumeResponse",
		"turn/start":     frozenV2ContractURL + "#/definitions/TurnStartResponse",
		"turn/steer":     frozenV2ContractURL + "#/definitions/TurnSteerResponse",
		"turn/interrupt": frozenV2ContractURL + "#/definitions/TurnInterruptResponse",
	}
	results := make(map[string]*jsonschema.Schema, len(resultPointers))
	for method, location := range resultPointers {
		schema, compileErr := compile(location)
		if compileErr != nil {
			return nil, compileErr
		}
		results[method] = schema
	}
	serverResults := make(map[string]*jsonschema.Schema, len(serverResultURLs))
	for method, location := range serverResultURLs {
		schema, compileErr := compile(location)
		if compileErr != nil {
			return nil, compileErr
		}
		serverResults[method] = schema
	}
	return &contractValidator{
		response: responseSchema, errorResponse: errorSchema,
		notification: notificationSchema, results: results,
		serverRequest: serverRequestSchema, serverResults: serverResults,
	}, nil
}

func (v *contractValidator) validateServerRequest(raw json.RawMessage) error {
	fields, err := decodeContractObject(raw)
	if err != nil || !hasOnlyServerRequestFields(fields) {
		return ErrContractViolation
	}
	value, err := decodeContractValue(raw)
	if err != nil || v.serverRequest.Validate(value) != nil {
		return ErrContractViolation
	}
	return nil
}

func (v *contractValidator) validateServerResponse(method string, raw, result json.RawMessage, rpcErr *RPCError) error {
	fields, err := decodeContractObject(raw)
	if err != nil || !hasOnlyResponseFields(fields, rpcErr != nil) {
		return ErrContractViolation
	}
	value, err := decodeContractValue(raw)
	if err != nil {
		return ErrContractViolation
	}
	if rpcErr != nil {
		if v.errorResponse.Validate(value) != nil {
			return ErrContractViolation
		}
		return nil
	}
	if v.response.Validate(value) != nil {
		return ErrContractViolation
	}
	schema := v.serverResults[method]
	resultValue, err := decodeContractValue(result)
	if schema == nil || err != nil || schema.Validate(resultValue) != nil {
		return ErrContractViolation
	}
	return nil
}

func (v *contractValidator) validateNotification(raw json.RawMessage) error {
	fields, err := decodeContractObject(raw)
	if err != nil || !hasOnlyNotificationFields(fields) {
		return ErrContractViolation
	}
	value, err := decodeContractValue(raw)
	if err != nil || v.notification.Validate(value) != nil {
		return ErrContractViolation
	}
	return nil
}

func (v *contractValidator) validateResponse(method string, raw, result json.RawMessage, rpcErr *RPCError) error {
	fields, err := decodeContractObject(raw)
	if err != nil || !hasOnlyResponseFields(fields, rpcErr != nil) {
		return ErrContractViolation
	}
	value, err := decodeContractValue(raw)
	if err != nil {
		return ErrContractViolation
	}
	if rpcErr != nil {
		if v.errorResponse.Validate(value) != nil {
			return ErrContractViolation
		}
		return nil
	}
	if v.response.Validate(value) != nil {
		return ErrContractViolation
	}
	if method == "" {
		return nil
	}
	schema := v.results[method]
	if schema == nil {
		return ErrContractViolation
	}
	resultValue, err := decodeContractValue(result)
	if err != nil || schema.Validate(resultValue) != nil {
		return ErrContractViolation
	}
	return nil
}

func decodeContractValue(raw json.RawMessage) (any, error) {
	return jsonschema.UnmarshalJSON(bytes.NewReader(raw))
}

func decodeContractObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("JSON-RPC message is not an object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return nil, errors.New("invalid JSON-RPC object")
		}
		name, ok := nameToken.(string)
		if !ok {
			return nil, errors.New("invalid JSON-RPC field name")
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, errors.New("duplicate JSON-RPC field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("invalid JSON-RPC field value")
		}
		fields[name] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("unterminated JSON-RPC object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON-RPC object has trailing data")
	}
	if version, ok := fields["jsonrpc"]; ok && string(version) != `"2.0"` {
		return nil, errors.New("unsupported JSON-RPC version")
	}
	return fields, nil
}

func hasOnlyNotificationFields(fields map[string]json.RawMessage) bool {
	if _, ok := fields["method"]; !ok {
		return false
	}
	if _, ok := fields["params"]; !ok {
		return false
	}
	for field := range fields {
		switch field {
		case "jsonrpc", "method", "params", "emittedAtMs":
		default:
			return false
		}
	}
	return true
}

func hasOnlyServerRequestFields(fields map[string]json.RawMessage) bool {
	id, hasID := fields["id"]
	if !hasID || string(id) == "null" {
		return false
	}
	if _, ok := fields["method"]; !ok {
		return false
	}
	if _, ok := fields["params"]; !ok {
		return false
	}
	for field := range fields {
		switch field {
		case "jsonrpc", "id", "method", "params":
		default:
			return false
		}
	}
	return true
}

func hasOnlyResponseFields(fields map[string]json.RawMessage, isError bool) bool {
	id, hasID := fields["id"]
	if !hasID || string(id) == "null" {
		return false
	}
	_, hasResult := fields["result"]
	_, hasError := fields["error"]
	if isError != hasError || isError == hasResult {
		return false
	}
	for field := range fields {
		switch field {
		case "jsonrpc", "id", "result", "error":
		default:
			return false
		}
	}
	return true
}

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DefaultConnectorVersion = "0.1.1"
	DefaultCodexVersion     = "0.147.0"
	PinnedSchemaDigest      = "511c1b3ca038a80740a5a41ca10a7f925c0f744e582fb9aaa03cc46c6e98b80b"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("duration must be a quoted value such as \"20s\"")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Value() time.Duration { return time.Duration(d) }

type Config struct {
	ControlURL          string   `json:"control_url"`
	PairingURL          string   `json:"pairing_url"`
	TokenURL            string   `json:"token_url"`
	DisplayName         string   `json:"display_name"`
	StateDir            string   `json:"state_dir"`
	WorkspaceRoots      []string `json:"workspace_roots"`
	SandboxCap          string   `json:"sandbox_cap"`
	CodexBinary         string   `json:"codex_binary"`
	CodexVersion        string   `json:"codex_version"`
	SchemaDigest        string   `json:"schema_digest"`
	HeartbeatInterval   Duration `json:"heartbeat_interval"`
	ApprovalTimeout     Duration `json:"approval_timeout"`
	PairingPollInterval Duration `json:"pairing_poll_interval"`
	ReconnectMin        Duration `json:"reconnect_min"`
	ReconnectMax        Duration `json:"reconnect_max"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode connector config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("connector config contains multiple JSON values")
		}
		return Config{}, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.SandboxCap == "" {
		c.SandboxCap = "workspace-write"
	}
	if c.CodexBinary == "" {
		c.CodexBinary = "codex"
	}
	if c.CodexVersion == "" {
		c.CodexVersion = DefaultCodexVersion
	}
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = Duration(20 * time.Second)
	}
	if c.ApprovalTimeout == 0 {
		c.ApprovalTimeout = Duration(120 * time.Second)
	}
	if c.PairingPollInterval == 0 {
		c.PairingPollInterval = Duration(2 * time.Second)
	}
	if c.ReconnectMin == 0 {
		c.ReconnectMin = Duration(time.Second)
	}
	if c.ReconnectMax == 0 {
		c.ReconnectMax = Duration(30 * time.Second)
	}
}

func (c *Config) Validate() error {
	if err := requireURL(c.ControlURL, "wss", "control_url"); err != nil {
		return err
	}
	if err := requireURL(c.PairingURL, "https", "pairing_url"); err != nil {
		return err
	}
	if err := requireURL(c.TokenURL, "https", "token_url"); err != nil {
		return err
	}
	controlOrigin, _ := url.Parse(c.ControlURL)
	pairingOrigin, _ := url.Parse(c.PairingURL)
	tokenOrigin, _ := url.Parse(c.TokenURL)
	if !strings.EqualFold(controlOrigin.Host, pairingOrigin.Host) || !strings.EqualFold(pairingOrigin.Host, tokenOrigin.Host) {
		return errors.New("control_url, pairing_url, and token_url must use the same origin host")
	}
	if strings.TrimSpace(c.DisplayName) == "" || utf8.RuneCountInString(c.DisplayName) > 255 {
		return errors.New("display_name is required")
	}
	c.DisplayName = strings.TrimSpace(c.DisplayName)
	if !filepath.IsAbs(c.StateDir) {
		return errors.New("state_dir must be an absolute path")
	}
	if len(c.WorkspaceRoots) == 0 || len(c.WorkspaceRoots) > 32 {
		return errors.New("workspace_roots must contain between 1 and 32 directories")
	}
	seen := make(map[string]struct{}, len(c.WorkspaceRoots))
	for i, root := range c.WorkspaceRoots {
		if !filepath.IsAbs(root) {
			return fmt.Errorf("workspace_roots[%d] must be absolute", i)
		}
		if len([]byte(root)) > 4096 || strings.IndexFunc(root, func(character rune) bool { return character < 0x20 }) >= 0 {
			return fmt.Errorf("workspace_roots[%d] has an invalid length or control character", i)
		}
		resolved, err := filepath.EvalSymlinks(filepath.Clean(root))
		if err != nil {
			return fmt.Errorf("resolve workspace_roots[%d]: %w", i, err)
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("workspace_roots[%d] is not a directory", i)
		}
		if resolved == string(filepath.Separator) {
			return errors.New("the filesystem root cannot be a workspace root")
		}
		if _, exists := seen[resolved]; exists {
			return fmt.Errorf("workspace root %q is duplicated", resolved)
		}
		seen[resolved] = struct{}{}
		c.WorkspaceRoots[i] = resolved
	}
	statePath, err := canonicalProspectivePath(c.StateDir)
	if err != nil {
		return fmt.Errorf("resolve state_dir: %w", err)
	}
	codexHome, err := effectiveCodexHome()
	if err != nil {
		return err
	}
	if pathsOverlap(codexHome, statePath) {
		return errors.New("state_dir must not overlap CODEX_HOME")
	}
	for _, root := range c.WorkspaceRoots {
		if pathsOverlap(root, codexHome) {
			return errors.New("workspace_roots must not overlap CODEX_HOME")
		}
		if pathsOverlap(root, statePath) {
			return errors.New("state_dir must not overlap a configured workspace root")
		}
	}
	c.StateDir = statePath
	if c.SandboxCap != "read-only" && c.SandboxCap != "workspace-write" {
		return errors.New("sandbox_cap must be read-only or workspace-write")
	}
	if strings.TrimSpace(c.CodexBinary) == "" || strings.ContainsRune(c.CodexBinary, '\x00') {
		return errors.New("codex_binary is invalid")
	}
	if c.CodexVersion != DefaultCodexVersion {
		return fmt.Errorf("codex_version must remain pinned to %s", DefaultCodexVersion)
	}
	if c.SchemaDigest != PinnedSchemaDigest {
		return fmt.Errorf("schema_digest must match the pinned Codex %s schema digest", DefaultCodexVersion)
	}
	if c.HeartbeatInterval.Value() < 5*time.Second || c.HeartbeatInterval.Value() > time.Minute {
		return errors.New("heartbeat_interval must be between 5s and 1m")
	}
	if c.ApprovalTimeout.Value() <= 0 || c.ApprovalTimeout.Value() > 120*time.Second {
		return errors.New("approval_timeout must be greater than zero and at most 120s")
	}
	if c.PairingPollInterval.Value() < 500*time.Millisecond || c.PairingPollInterval.Value() > 10*time.Second {
		return errors.New("pairing_poll_interval must be between 500ms and 10s")
	}
	if c.ReconnectMin.Value() < 100*time.Millisecond || c.ReconnectMax.Value() < c.ReconnectMin.Value() || c.ReconnectMax.Value() > 5*time.Minute {
		return errors.New("reconnect_min must be at least 100ms and reconnect_max must be no more than 5m")
	}
	return nil
}

func effectiveCodexHome() (string, error) {
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve default CODEX_HOME: %w", err)
		}
		home = filepath.Join(userHome, ".codex")
	}
	if !filepath.IsAbs(home) {
		return "", errors.New("CODEX_HOME must be an absolute path")
	}
	resolved, err := canonicalProspectivePath(home)
	if err != nil {
		return "", fmt.Errorf("resolve CODEX_HOME: %w", err)
	}
	return resolved, nil
}

func canonicalProspectivePath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	current := cleaned
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved), nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func pathsOverlap(first, second string) bool {
	contains := func(parent, child string) bool {
		relative, err := filepath.Rel(parent, child)
		return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	return contains(first, second) || contains(second, first)
}

func requireURL(raw, scheme, field string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != scheme || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an absolute %s URL without user info", field, scheme)
	}
	return nil
}

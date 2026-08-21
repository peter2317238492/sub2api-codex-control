package appserver_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/appserver"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/config"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
)

func TestLivePinnedCodexAppServerAndOrdinaryCLIStayIndependent(t *testing.T) {
	if os.Getenv("SUB2API_CODEX_LIVE_INTEGRATION") != "1" {
		t.Skip("set SUB2API_CODEX_LIVE_INTEGRATION=1 to test the installed pinned Codex app-server")
	}
	binary := os.Getenv("SUB2API_CODEX_BINARY")
	if binary == "" {
		binary = "codex"
	}
	assertCodexProtectedStateUnchanged(t)
	beforeCLI := runOrdinaryCLI(t, binary)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	client, err := appserver.Start(ctx, appserver.StartOptions{
		Binary: binary, ExpectedVersion: config.DefaultCodexVersion,
		ConnectorVersion:  config.DefaultConnectorVersion,
		InitializeTimeout: 15 * time.Second, Stderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("pinned Codex app-server failed to initialize: %v", err)
	}
	closed := false
	stopListenerMonitor, listenerMonitorDone := monitorProcessGroupListeners(t, client.ProcessID())
	monitorStopped := false
	t.Cleanup(func() {
		if !monitorStopped {
			stopListenerMonitor()
			<-listenerMonitorDone
		}
		if !closed {
			client.Close()
			_ = client.Wait()
		}
	})
	duringCLI := runOrdinaryCLI(t, binary)

	callCtx, cancelCall := context.WithTimeout(ctx, 15*time.Second)
	defer cancelCall()
	raw, err := client.Call(callCtx, "model/list", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("pinned Codex app-server rejected model/list: %v", err)
	}
	projected, err := policy.ProjectResult("model/list", raw)
	if err != nil {
		t.Fatal("model/list response did not match the frozen safe projection")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(projected, &envelope); err != nil {
		t.Fatal("projected model/list response is not valid JSON")
	}
	if _, found := firstCollection(envelope, "data", "models", "items"); !found {
		t.Fatal("projected model/list response has no recognized collection")
	}

	client.Close()
	// The job object on Windows and the process group on POSIX are what
	// guarantee the tree is gone. ErrWaitDelay reports only that the child's
	// I/O pipes outlived it, which a console-subsystem process outside the job
	// can cause on Windows, so the guarantee itself is asserted below instead
	// of the incidental pipe timing.
	if err := client.Wait(); err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("pinned Codex app-server did not stop cleanly: %v", err)
	}
	assertProcessTreeTerminated(t, client.ProcessID())
	closed = true
	stopListenerMonitor()
	if err := <-listenerMonitorDone; err != nil {
		t.Fatal(err)
	}
	monitorStopped = true
	afterCLI := runOrdinaryCLI(t, binary)
	if !bytes.Equal(beforeCLI, duringCLI) || !bytes.Equal(beforeCLI, afterCLI) {
		t.Fatal("ordinary Codex CLI output changed while the Connector-owned app-server ran or stopped")
	}
}

// monitorProcessGroupListeners polls the Connector-owned app-server process
// tree for inbound sockets. The Connector never listens on a local port, and
// this is the live proof of it; the platform probe that enumerates the tree is
// supplied by listener_probe_unix_test.go and listener_probe_windows_test.go.
func monitorProcessGroupListeners(t *testing.T, processGroupID int) (context.CancelFunc, <-chan error) {
	t.Helper()
	probe := newListenerProbe(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			if err := probe(ctx, processGroupID); err != nil {
				done <- err
				return
			}
			select {
			case <-ctx.Done():
				done <- nil
				return
			case <-ticker.C:
			}
		}
	}()
	return cancel, done
}

func runOrdinaryCLI(t *testing.T, binary string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "features", "list")
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil {
		t.Fatalf("ordinary pinned Codex CLI operation failed: %v", err)
	}
	if len(bytes.TrimSpace(output)) == 0 {
		t.Fatal("ordinary pinned Codex CLI operation returned no feature state")
	}
	return output
}

func firstCollection(envelope map[string]json.RawMessage, fields ...string) (json.RawMessage, bool) {
	for _, field := range fields {
		if collection, ok := envelope[field]; ok {
			return collection, true
		}
	}
	return nil, false
}

func TestProtectedCodexStateManifestDetectsRelevantChanges(t *testing.T) {
	home := t.TempDir()
	configPath := filepath.Join(home, "config.toml")
	if err := os.WriteFile(configPath, []byte("model = 'pinned'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(home, "plugins", "example")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pluginPath := filepath.Join(pluginDir, "manifest.json")
	if err := os.WriteFile(pluginPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	baseline, err := protectedCodexStateManifest(home)
	if err != nil {
		t.Fatal(err)
	}
	stable, err := protectedCodexStateManifest(home)
	if err != nil || stable != baseline {
		t.Fatal("protected state manifest is not stable")
	}

	if err := os.WriteFile(configPath, []byte("model = 'changed'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertProtectedManifestChanged(t, home, baseline, "config content")
	if err := os.WriteFile(configPath, []byte("model = 'pinned'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Clearing owner write is the one permission change every platform records:
	// Windows reports only the read-only attribute through fs.FileMode.
	if err := os.Chmod(configPath, 0o400); err != nil {
		t.Fatal(err)
	}
	assertProtectedManifestChanged(t, home, baseline, "config mode")
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(home, "auth-provider.json")
	if err := os.WriteFile(authPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertProtectedManifestChanged(t, home, baseline, "new auth file")
	if err := os.Remove(authPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pluginPath, []byte("{\"changed\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertProtectedManifestChanged(t, home, baseline, "plugin content")
}

func assertProtectedManifestChanged(
	t *testing.T,
	home string,
	baseline [sha256.Size]byte,
	description string,
) {
	t.Helper()
	changed, err := protectedCodexStateManifest(home)
	if err != nil {
		t.Fatal(err)
	}
	if changed == baseline {
		t.Fatalf("protected state manifest missed %s", description)
	}
}

type protectedStateEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}

func assertCodexProtectedStateUnchanged(t *testing.T) {
	t.Helper()
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			t.Fatal("cannot locate Codex home for integrity check")
		}
		home = filepath.Join(userHome, ".codex")
	}
	before, err := protectedCodexStateManifest(home)
	if err != nil {
		t.Fatal("cannot read the protected Codex state manifest")
	}
	t.Cleanup(func() {
		after, err := protectedCodexStateManifest(home)
		if err != nil || after != before {
			t.Errorf("live app-server test modified protected Codex config, auth, provider, or plugin state")
		}
	})
}

func protectedCodexStateManifest(home string) ([sha256.Size]byte, error) {
	directoryEntries, err := os.ReadDir(home)
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	paths := make(map[string]struct{})
	for _, entry := range directoryEntries {
		configMatch := strings.HasPrefix(entry.Name(), "config") && strings.HasSuffix(entry.Name(), ".toml")
		authMatch := strings.HasPrefix(entry.Name(), "auth") && strings.HasSuffix(entry.Name(), ".json")
		if configMatch || authMatch {
			paths[filepath.Join(home, entry.Name())] = struct{}{}
		}
	}

	records := make([]protectedStateEntry, 0, len(paths)+2)
	for _, directory := range []string{"plugins", "providers"} {
		root := filepath.Join(home, directory)
		if _, err := os.Lstat(root); os.IsNotExist(err) {
			records = append(records, protectedStateEntry{Path: directory, Type: "missing"})
			continue
		} else if err != nil {
			return [sha256.Size]byte{}, err
		}
		if err := filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			paths[path] = struct{}{}
			return nil
		}); err != nil {
			return [sha256.Size]byte{}, err
		}
	}

	sortedPaths := make([]string, 0, len(paths))
	for path := range paths {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Slice(sortedPaths, func(i, j int) bool {
		left, _ := filepath.Rel(home, sortedPaths[i])
		right, _ := filepath.Rel(home, sortedPaths[j])
		return filepath.ToSlash(left) < filepath.ToSlash(right)
	})
	for _, path := range sortedPaths {
		record, err := protectedCodexStateEntry(home, path)
		if err != nil {
			return [sha256.Size]byte{}, err
		}
		records = append(records, record)
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func protectedCodexStateEntry(home, path string) (protectedStateEntry, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return protectedStateEntry{}, err
	}
	relative, err := filepath.Rel(home, path)
	if err != nil {
		return protectedStateEntry{}, err
	}
	record := protectedStateEntry{
		Path: filepath.ToSlash(relative),
		Mode: uint32(info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)),
	}
	switch {
	case info.Mode().IsRegular():
		content, err := os.ReadFile(path)
		if err != nil {
			return protectedStateEntry{}, err
		}
		digest := sha256.Sum256(content)
		record.Type = "file"
		record.SHA256 = hex.EncodeToString(digest[:])
	case info.IsDir():
		record.Type = "directory"
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return protectedStateEntry{}, err
		}
		record.Type = "symlink"
		record.Target = target
	default:
		record.Type = "other"
	}
	return record, nil
}

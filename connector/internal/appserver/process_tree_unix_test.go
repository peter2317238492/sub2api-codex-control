//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package appserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCloseAllowsBoundedStdioShutdownBeforeForcing(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "graceful")
	script := filepath.Join(dir, "fake-codex")
	contents := fmt.Sprintf(`#!/bin/sh
if test "$1" = "--version"; then
  printf 'codex-cli 0.147.0\n'
  exit 0
fi
IFS= read -r initialize || exit 40
printf '%%s\n' '{"jsonrpc":"2.0","id":1,"result":{"codexHome":"/tmp/fake-codex-home","platformFamily":"unix","platformOs":"linux","userAgent":"fake"}}'
IFS= read -r initialized || exit 41
while IFS= read -r request; do :; done
printf 'graceful\n' > %q
`, marker)
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	client, err := Start(context.Background(), StartOptions{
		Binary: script, ExpectedVersion: "0.147.0", ConnectorVersion: "test",
		InitializeTimeout: time.Second, ShutdownGracePeriod: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := client.Wait(); err != nil {
		t.Fatalf("graceful app-server exit failed: %v", err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "graceful\n" {
		t.Fatalf("stdio shutdown marker = %q, %v", data, err)
	}
}

func TestForcedShutdownKillsTheConnectorOwnedProcessGroup(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "descendant.pid")
	script := filepath.Join(dir, "fake-codex")
	contents := fmt.Sprintf(`#!/bin/sh
if test "$1" = "--version"; then
  printf 'codex-cli 0.147.0\n'
  exit 0
fi
IFS= read -r initialize || exit 40
printf '%%s\n' '{"jsonrpc":"2.0","id":1,"result":{"codexHome":"/tmp/fake-codex-home","platformFamily":"unix","platformOs":"linux","userAgent":"fake"}}'
IFS= read -r initialized || exit 41
/bin/sleep 30 &
printf '%%s\n' "$!" > %q
while :; do /bin/sleep 30; done
`, pidPath)
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	client, err := Start(context.Background(), StartOptions{
		Binary: script, ExpectedVersion: "0.147.0", ConnectorVersion: "test",
		InitializeTimeout: time.Second, ShutdownGracePeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	data := waitForProcessID(t, pidPath)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		t.Fatalf("descendant pid = %q, %v", data, err)
	}

	client.Close()
	if err := client.Wait(); err == nil {
		t.Fatal("forced app-server shutdown unexpectedly reported a clean exit")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		err = syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("app-server descendant %d survived process-group shutdown", pid)
}

func waitForProcessID(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return data
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for descendant pid")
	return nil
}
